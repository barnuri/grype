package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	"github.com/spf13/cobra"
)

var cveIDs []string

var explainCmd = &cobra.Command{
	Use:   "explain --cve [CVE ID]",
	Short: "Ask grype to explain a set of findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		isStdinPipeOrRedirect, err := internal.IsStdinPipeOrRedirect()
		if err != nil {
			log.Warnf("unable to determine if there is piped input: %+v", err)
			isStdinPipeOrRedirect = false
		}
		if isStdinPipeOrRedirect {
			// TODO: eventually detect different types of input; for now assume grype json
			var parseResult models.Document
			decoder := json.NewDecoder(os.Stdin)
			err := decoder.Decode(&parseResult)
			if err != nil {
				return fmt.Errorf("unable to parse piped input: %+v", err)
			}
			explainer := models.NewVulnerabilityExplainer(parseResult, os.Stdout)
			return explainer.ExplainByID(cveIDs)
		} else {
			// perform a scan, then explain requested CVEs
			// TODO: implement
			return fmt.Errorf("not implemented")
		}
	},
}

func init() {
	setExplainFlags(explainCmd)
}

func setExplainFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(&cveIDs, "cve", "", nil, "CVE ID to explain")
}

type CveFilter func(models.Match) bool

func byeCVEId(cveID string) CveFilter {
	return func(m models.Match) bool {
		return m.Vulnerability.ID == cveID
	}
}

func orFilter(orFilters ...CveFilter) CveFilter {
	return func(m models.Match) bool {
		for _, f := range orFilters {
			if f(m) {
				return true
			}
		}
		return false
	}
}

func filterMatches(matches []models.Match, filter CveFilter) []models.Match {
	var result []models.Match
	for _, m := range matches {
		if filter(m) {
			result = append(result, m)
		}
	}
	return result
}

var explanationTemplate string = `{{ .Vulnerability.ID }} is from {{ .Vulnerability.DataSource }}
is matched by{{ range .MatchDetails }} {{ .Type }} {{ displayFound . }}{{ end }}.
The matched artifact is:
	{{ .Artifact.Name }} {{ .Artifact.PURL }}
The URLs for related vulnerabilities are:
{{ range .Vulnerability.VulnerabilityMetadata.URLs }}	- {{ . }}
{{ end }}
`

func displayFoundReason(md models.MatchDetails) string {
	if cper, ok := md.Found.(search.CPEResult); ok {
		return fmt.Sprintf("(relevant CPEs: `%s`)", strings.Join(cper.CPEs, ", "))
	}
	if mapStr, ok := md.Found.(map[string]interface{}); ok && len(mapStr) > 0 {
		var sb strings.Builder
		sb.WriteString("(")
		sep := ""
		for k, v := range mapStr {
			sb.WriteString(sep)
			sb.WriteString(fmt.Sprintf("%s: %v", k, v))
			sep = ", "
		}
		sb.WriteString(")")
		return sb.String()
	}
	return ""
}

func deduplicateMatchesByCVE(matches []models.Match) map[string]models.Match {
	result := make(map[string]models.Match)
	for _, m := range matches {
		result[m.Vulnerability.ID] = m
	}
	return result
}
