package search

import (
	"strings"
	"testing"
)

// The bounds count runes after trimming surrounding white space, so a padded
// two-letter term stays too short and 64 accented letters stay acceptable.
// A blank input means "no search" and is valid; control runes and invalid UTF-8
// are refused because they never come from a typed search and PostgreSQL rejects
// NUL in text values.
func TestParseTermEnforcesBoundsAfterTrim(testContext *testing.T) {
	parseCases := []struct {
		rawTerm       string
		expectedTerm  string
		expectedValid bool
	}{
		{rawTerm: "", expectedTerm: "", expectedValid: true},
		{rawTerm: "   ", expectedTerm: "", expectedValid: true},
		{rawTerm: "ab", expectedTerm: "", expectedValid: false},
		{rawTerm: "  ab  ", expectedTerm: "", expectedValid: false},
		{rawTerm: " abc ", expectedTerm: "abc", expectedValid: true},
		{rawTerm: strings.Repeat("é", 64), expectedTerm: strings.Repeat("é", 64), expectedValid: true},
		{rawTerm: strings.Repeat("a", 65), expectedTerm: "", expectedValid: false},
		{rawTerm: "ab\x00c", expectedTerm: "", expectedValid: false},
		{rawTerm: "ab\tcd", expectedTerm: "", expectedValid: false},
		{rawTerm: "ab\xffcd", expectedTerm: "", expectedValid: false},
		{rawTerm: "a'b", expectedTerm: "a'b", expectedValid: true},
		{rawTerm: "'); --", expectedTerm: "'); --", expectedValid: true},
	}
	for _, parseCase := range parseCases {
		obtainedTerm, obtainedValid := ParseTerm(parseCase.rawTerm)
		if obtainedTerm != parseCase.expectedTerm || obtainedValid != parseCase.expectedValid {
			testContext.Errorf("ParseTerm(%q) = (%q, %v), want (%q, %v)",
				parseCase.rawTerm, obtainedTerm, obtainedValid, parseCase.expectedTerm, parseCase.expectedValid)
		}
	}
}

// The pattern is meant for "ILIKE ? ESCAPE '\'": every LIKE metacharacter of the
// term is escaped with a backslash so it matches itself, and the term is wrapped
// in % to match anywhere.
func TestContainsPatternEscapesLikeMetacharacters(testContext *testing.T) {
	patternCases := map[string]string{
		"198.51": "%198.51%",
		"a%b":    `%a\%b%`,
		"a_b":    `%a\_b%`,
		`a\b`:    `%a\\b%`,
		`%_\`:    `%\%\_\\%`,
		"a'b":    "%a'b%",
		"'); --": "%'); --%",
	}
	for term, expectedPattern := range patternCases {
		if obtainedPattern := ContainsPattern(term); obtainedPattern != expectedPattern {
			testContext.Errorf("ContainsPattern(%q) = %q, want %q", term, obtainedPattern, expectedPattern)
		}
	}
}

func TestMatchesIsACaseInsensitiveLiteralSubstring(testContext *testing.T) {
	matchCases := []struct {
		term           string
		candidateTexts []string
		expectedMatch  bool
	}{
		{term: "SSH-BF", candidateTexts: []string{"crowdsecurity/ssh-bf"}, expectedMatch: true},
		{term: "a%b", candidateTexts: []string{"axxb"}, expectedMatch: false},
		{term: "a%b", candidateTexts: []string{"test/a%b"}, expectedMatch: true},
		{term: "a_b", candidateTexts: []string{"axb"}, expectedMatch: false},
		{term: `a\b`, candidateTexts: []string{"ab"}, expectedMatch: false},
		{term: "peer", candidateTexts: []string{"", "peer-a"}, expectedMatch: true},
		{term: "peer", candidateTexts: []string{"local", "web-01"}, expectedMatch: false},
		{term: "peer", candidateTexts: nil, expectedMatch: false},
		{term: "", candidateTexts: []string{"anything"}, expectedMatch: true},
		{term: "a'b", candidateTexts: []string{"test/a'b"}, expectedMatch: true},
		{term: "a'b", candidateTexts: []string{"test/ab"}, expectedMatch: false},
	}
	for _, matchCase := range matchCases {
		if obtainedMatch := Matches(matchCase.term, matchCase.candidateTexts...); obtainedMatch != matchCase.expectedMatch {
			testContext.Errorf("Matches(%q, %q) = %v, want %v",
				matchCase.term, matchCase.candidateTexts, obtainedMatch, matchCase.expectedMatch)
		}
	}
}

// Non-ASCII rule: Matches lowers term and candidates rune by rune with
// strings.ToLower (Unicode simple lower-case mapping), with no full case folding
// and no accent stripping. So "éco" finds "ÉCOLE", "istan" finds "İSTANBUL",
// "k" finds the Kelvin sign, but "STRASSE" does not find "straße", "eco" does not
// find "école", and the final sigma "ς" stays distinct from "σ". PostgreSQL ILIKE
// on an en_US.utf8 database gave the same answer for each of these pairs; on a
// database whose LC_CTYPE is C, ILIKE folds ASCII letters only, so the archive
// may miss a non-ASCII case variant the live window finds. ASCII behaves the same
// everywhere.
func TestMatchesLowersNonASCIILettersRuneByRuneWithoutFolding(testContext *testing.T) {
	matchCases := []struct {
		term          string
		candidateText string
		expectedMatch bool
	}{
		{term: "éco", candidateText: "ÉCOLE", expectedMatch: true},
		{term: "ÉCO", candidateText: "école", expectedMatch: true},
		{term: "istan", candidateText: "İSTANBUL", expectedMatch: true},
		{term: "kel", candidateText: "Kelvin", expectedMatch: true},
		{term: "STRASSE", candidateText: "straße", expectedMatch: false},
		{term: "eco", candidateText: "école", expectedMatch: false},
		{term: "σας", candidateText: "ΣΑΣ", expectedMatch: false},
	}
	for _, matchCase := range matchCases {
		if obtainedMatch := Matches(matchCase.term, matchCase.candidateText); obtainedMatch != matchCase.expectedMatch {
			testContext.Errorf("Matches(%q, %q) = %v, want %v",
				matchCase.term, matchCase.candidateText, obtainedMatch, matchCase.expectedMatch)
		}
	}
}
