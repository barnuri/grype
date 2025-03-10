package v6

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/schemaver"
)

func TestReadDescription(t *testing.T) {
	tempDir := t.TempDir()

	s, err := NewWriter(Config{DBDirPath: tempDir})
	require.NoError(t, err)
	require.NoError(t, s.SetDBMetadata())
	expected, err := s.GetDBMetadata()
	require.NoError(t, err)
	require.NoError(t, s.Close())

	dbFilePath := path.Join(tempDir, VulnerabilityDBFileName)

	description, err := ReadDescription(dbFilePath)
	require.NoError(t, err)
	require.NotNil(t, description)

	assert.Equal(t, Description{
		SchemaVersion: schemaver.New(expected.Model, expected.Revision, expected.Addition),
		Built:         Time{*expected.BuildTimestamp},
	}, *description)
}

func TestTime_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name     string
		time     Time
		expected string
	}{
		{
			name:     "go case",
			time:     Time{time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
			expected: `"2023-09-26T12:00:00Z"`,
		},
		{
			name:     "convert to utc",
			time:     Time{time.Date(2023, 9, 26, 13, 0, 0, 0, time.FixedZone("UTC+1", 3600))},
			expected: `"2023-09-26T12:00:00Z"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.time)
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(jsonData))
		})
	}
}

func TestTime_JSONUnmarshalling(t *testing.T) {
	tests := []struct {
		name         string
		jsonData     string
		expectedTime Time
		expectError  require.ErrorAssertionFunc
	}{
		{
			name:         "use zulu offset",
			jsonData:     `"2023-09-26T12:00:00Z"`,
			expectedTime: Time{time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
		},
		{
			name:         "use tz offset in another timezone",
			jsonData:     `"2023-09-26T14:00:00+02:00"`,
			expectedTime: Time{time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
		},
		{
			name:         "use tz offset that is utc",
			jsonData:     `"2023-09-26T12:00:00+00:00"`,
			expectedTime: Time{time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
		},
		{
			name:        "invalid format",
			jsonData:    `"invalid-time-format"`,
			expectError: require.Error,
		},
		{
			name:        "invalid json",
			jsonData:    `invalid`,
			expectError: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectError == nil {
				tt.expectError = require.NoError
			}
			var parsedTime Time
			err := json.Unmarshal([]byte(tt.jsonData), &parsedTime)
			tt.expectError(t, err)
			if err == nil {
				assert.Equal(t, tt.expectedTime.Time, parsedTime.Time)
			}
		})
	}
}

func TestWriteChecksums(t *testing.T) {

	cases := []struct {
		name     string
		digest   string
		expected string
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "go case",
			digest:   "xxh64:dummychecksum",
			expected: "xxh64:dummychecksum",
		},
		{
			name:    "empty checksum",
			wantErr: require.Error,
		},
		{
			name:    "missing prefix",
			digest:  "dummychecksum",
			wantErr: require.Error,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == nil {
				tc.wantErr = require.NoError
			}
			sb := strings.Builder{}
			err := WriteChecksums(&sb, tc.digest)
			tc.wantErr(t, err)
			if err == nil {
				assert.Equal(t, tc.expected, sb.String())
			}
		})
	}
}

func TestReadDBChecksum(t *testing.T) {
	tests := []struct {
		name             string
		checksumContent  string
		expectedErr      string
		expectedChecksum string
	}{
		{
			name:            "checksum file missing",
			checksumContent: "",
			expectedErr:     "failed to read checksums file",
		},
		{
			name:            "invalid checksum format",
			checksumContent: "invalid",
			expectedErr:     "checksums file is not in the expected format",
		},
		{
			name:             "valid checksum format",
			checksumContent:  "xxh64:checksum",
			expectedChecksum: "xxh64:checksum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.checksumContent != "" {
				err := os.WriteFile(filepath.Join(dir, ChecksumFileName), []byte(tt.checksumContent), 0644)
				require.NoError(t, err)
			}

			checksum, err := ReadDBChecksum(dir)

			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Empty(t, checksum)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedChecksum, checksum)
			}
		})
	}
}

func TestCalculateDigest(t *testing.T) {
	tests := []struct {
		name           string
		fileContent    string
		expectedErr    string
		expectedDigest string
	}{
		{
			name:        "file does not exist",
			fileContent: "",
			expectedErr: "failed to calculate checksum for DB file",
		},
		{
			name:           "valid file",
			fileContent:    "testcontent",
			expectedDigest: "xxh64:d37ed71e4fee2ebd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			filePath := filepath.Join(dir, VulnerabilityDBFileName)

			if tt.fileContent != "" {
				err := os.WriteFile(filePath, []byte(tt.fileContent), 0644)
				require.NoError(t, err)
			}

			digest, err := CalculateDBDigest(filePath)

			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Empty(t, digest)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedDigest, digest)
			}
		})
	}
}
