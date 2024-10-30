package pkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func Test_PurlProvider(t *testing.T) {
	tests := []struct {
		name      string
		userInput string
		context   Context
		pkgs      []Package
		wantErr   require.ErrorAssertionFunc
	}{
		{
			name:      "takes a single purl",
			userInput: "pkg:apk/curl@7.61.1",
			context:   Context{},
			pkgs: []Package{
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1",
				},
			},
		},
		{
			name:      "os with codename",
			userInput: "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
			context: Context{
				Distro: &linux.Release{
					Name:            "debian",
					ID:              "debian",
					IDLike:          []string{"debian"},
					VersionCodename: "jessie", // important!
				},
			},
			pkgs: []Package{
				{
					Name:    "sysv-rc",
					Version: "2.88dsf-59",
					Type:    pkg.DebPkg,
					PURL:    "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
					Upstreams: []UpstreamPackage{
						{
							Name: "sysvinit",
						},
					},
				},
			},
		},
		{
			name:      "default upstream",
			userInput: "pkg:apk/libcrypto3@3.3.2?upstream=openssl",
			context:   Context{},
			pkgs: []Package{
				{
					Name:    "libcrypto3",
					Version: "3.3.2",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/libcrypto3@3.3.2?upstream=openssl",
					Upstreams: []UpstreamPackage{
						{
							Name: "openssl",
						},
					},
				},
			},
		},
		{
			name:      "upstream with version",
			userInput: "pkg:apk/libcrypto3@3.3.2?upstream=openssl%403.2.1", // %40 is @
			context:   Context{},
			pkgs: []Package{
				{
					Name:    "libcrypto3",
					Version: "3.3.2",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/libcrypto3@3.3.2?upstream=openssl%403.2.1",
					Upstreams: []UpstreamPackage{
						{
							Name:    "openssl",
							Version: "3.2.1",
						},
					},
				},
			},
		},
		{
			name:      "upstream for source RPM",
			userInput: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
			context: Context{
				Distro: &linux.Release{
					Name:    "rhel",
					ID:      "rhel",
					IDLike:  []string{"rhel"},
					Version: "8.10",
				},
			},
			pkgs: []Package{
				{
					Name:    "systemd-x",
					Version: "0:239-82.el8_10.2",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
					Upstreams: []UpstreamPackage{
						{
							Name:    "systemd",
							Version: "239-82.el8_10.2",
						},
					},
				},
			},
		},
		{
			name:      "RPM with epoch",
			userInput: "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
			context: Context{
				Distro: &linux.Release{
					Name:    "rhel",
					ID:      "rhel",
					IDLike:  []string{"rhel"},
					Version: "8.10",
				},
			},
			pkgs: []Package{
				{
					Name:    "dbus-common",
					Version: "1:1.12.8-26.el8",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
					Upstreams: []UpstreamPackage{
						{
							Name:    "dbus",
							Version: "1.12.8-26.el8",
						},
					},
				},
			},
		},
		{
			name:      "takes multiple purls",
			userInput: "purl:test-fixtures/purl/valid-purl.txt",
			context: Context{
				Distro: &linux.Release{
					Name:    "debian",
					ID:      "debian",
					IDLike:  []string{"debian"},
					Version: "8",
				},
			},
			pkgs: []Package{
				{
					Name:    "sysv-rc",
					Version: "2.88dsf-59",
					Type:    pkg.DebPkg,
					PURL:    "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-8&upstream=sysvinit",
					Upstreams: []UpstreamPackage{
						{
							Name: "sysvinit",
						},
					},
				},
				{
					Name:    "ant",
					Version: "1.10.8",
					Type:    pkg.JavaPkg,
					PURL:    "pkg:maven/org.apache.ant/ant@1.10.8",
				},
				{
					Name:    "log4j-core",
					Version: "2.14.1",
					Type:    pkg.JavaPkg,
					PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
				},
			},
		},
		{
			name:      "infer context when distro is present for single purl",
			userInput: "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
			context: Context{
				Distro: &linux.Release{
					Name:    "alpine",
					ID:      "alpine",
					IDLike:  []string{"alpine"},
					Version: "3.20.3",
				},
			},
			pkgs: []Package{
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
				},
			},
		},
		{
			name:      "infer context when distro is present for multiple similar purls",
			userInput: "purl:test-fixtures/purl/homogeneous-os.txt",
			context: Context{
				Distro: &linux.Release{
					Name:    "alpine",
					ID:      "alpine",
					IDLike:  []string{"alpine"},
					Version: "3.20.3",
				},
			},
			pkgs: []Package{
				{
					Name:    "openssl",
					Version: "3.2.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/openssl@3.2.1?arch=aarch64&distro=alpine-3.20.3",
				},
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
				},
			},
		},
		{
			name:      "different distro info in purls does not infer context",
			userInput: "purl:test-fixtures/purl/different-os.txt",
			context:   Context{
				// important: no distro info inferred
			},
			pkgs: []Package{
				{
					Name:    "openssl",
					Version: "3.2.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/openssl@3.2.1?arch=aarch64&distro=alpine-3.20.3",
				},
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.2",
				},
			},
		},
		{
			name:      "fails on path with nonexistant file",
			userInput: "purl:tttt/empty.txt",
			wantErr:   require.Error,
		},
		{
			name:      "fails on invalid path",
			userInput: "purl:~&&",
			wantErr:   require.Error,
		},
		{
			name:      "allow empty purl file",
			userInput: "purl:test-fixtures/purl/empty.json",
		},
		{
			name:      "fails on invalid purl in file",
			userInput: "purl:test-fixtures/purl/invalid-purl.txt",
			wantErr:   require.Error,
		},
		{
			name:      "fails on invalid cpe in file",
			userInput: "purl:test-fixtures/purl/invalid-cpe.txt",
			wantErr:   require.Error,
		},
		{
			name:      "invalid prefix",
			userInput: "dir:test-fixtures/purl",
			wantErr:   require.Error,
		},
	}

	opts := []cmp.Option{
		cmpopts.IgnoreFields(Package{}, "ID", "Locations", "Licenses", "Metadata", "Language", "CPEs"),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == nil {
				tc.wantErr = require.NoError
			}

			packages, ctx, err := purlProvider(tc.userInput)

			tc.wantErr(t, err)
			if err != nil {
				require.Nil(t, packages)
				return
			}

			if d := cmp.Diff(tc.context, ctx, opts...); d != "" {
				t.Errorf("unexpected context (-want +got):\n%s", d)
			}
			require.Len(t, packages, len(tc.pkgs))
			for idx, expected := range tc.pkgs {
				if d := cmp.Diff(expected, packages[idx], opts...); d != "" {
					t.Errorf("unexpected context (-want +got):\n%s", d)
				}
			}
		})
	}
}
