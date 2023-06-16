package explanation

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

type Presenter struct {
	matches          match.Matches
	ignoredMatches   []match.IgnoredMatch
	packages         []pkg.Package
	context          pkg.Context
	metadataProvider vulnerability.MetadataProvider
	appConfig        interface{}
	dbStatus         interface{}
	ToBeExplained    []string
}

// NewPresenter creates a new JSON presenter
func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		matches:          pb.Matches,
		ignoredMatches:   pb.IgnoredMatches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		context:          pb.Context,
		appConfig:        pb.AppConfig,
		dbStatus:         pb.DBStatus,
		ToBeExplained:    pb.ToBeExplained,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := models.NewDocument(pres.packages, pres.context, pres.matches, pres.ignoredMatches, pres.metadataProvider,
		pres.appConfig, pres.dbStatus)
	if err != nil {
		return err
	}

	shouldBeExplained := make(map[string]bool)
	for _, te := range pres.ToBeExplained {
		shouldBeExplained[te] = true
	}

	var toExplain []models.Match
	for _, m := range doc.Matches {
		// TODO: this prints CVEs repeatedly
		if _, ok := shouldBeExplained[m.Vulnerability.ID]; ok {
			toExplain = append(toExplain, m)
			continue
		}
		// for _, rv := range m.RelatedVulnerabilities {
		// 	if _, ok := shouldBeExplained[rv.ID]; ok {
		// 		toExplain = append(toExplain, m)
		// 		continue
		// 	}
		// }
	}
	funcMap := template.FuncMap{
		"displayFound": DisplayFoundReason,
	}
	t := template.Must(template.New("explainer").Funcs(funcMap).Parse(templ))
	for _, m := range toExplain {
		var matchTypes []string
		for _, d := range m.MatchDetails {
			matchTypes = append(matchTypes, d.Type)
		}
		if err := t.Execute(output, m); err != nil {
			return err
		}
	}
	return nil
}

func DisplayFoundReason(md models.MatchDetails) string {
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

// var formatStr string = `%s from %s, of match type(s) %s.
// The matched package is %s (pURL: %s)
// `
var templ string = `{{ .Vulnerability.ID }} is from {{ .Vulnerability.DataSource }}
is matched by{{ range .MatchDetails }} {{ .Type }} {{ displayFound . }}{{ end }}.
The matched artifact is:
	{{ .Artifact.Name }} {{ .Artifact.PURL }}
The URLs for related vulnerabilities are:
{{ range .Vulnerability.VulnerabilityMetadata.URLs }}	- {{ . }}
{{ end }}
`

/*
CVE-2022-21510 from https://nvd.nist.gov/vuln/detail/CVE-2022-21510
matched artifact is:
   ojdbc11 - pkg:maven/com.oracle.database.jdbc/ojdbc11@21.4.0.0
match type is cpe-match
CPEs
  - `cpe:2.3:a:sun-microsystems-inc-:database:21.4.0.0:*:*:*:*:*:*:*`
  - `cpe:2.3:a:sun_microsystems_inc_:database:21.4.0.0:*:*:*:*:*:*:*`


URLs:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-21510
  - https://www.oracle.com/security-alerts/cpujul2022.html
*/
