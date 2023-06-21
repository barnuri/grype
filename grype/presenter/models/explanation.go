package models

import "github.com/anchore/grype/grype/match"

// Explanation represents the information used by grype to determine
// that the vulnerability is present. It is a view model meant to
// enable the UI to explain findings to the user.
type Explanation struct {
	cveID     string
	matchType match.Type
}

// NewFromMatchDetails takes a match details and returns an
// Explanation model that explains it.
func NewFromMatchDetails(md MatchDetails) *Explanation {

	return nil
}

// Display returns a human-readable string representing
// the Explanation.
func (e Explanation) Display() string {
	return ""
}
