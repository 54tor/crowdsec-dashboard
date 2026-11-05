package search

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MinimumTermRunes = 3
	MaximumTermRunes = 64
)

var likeMetacharacterEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func ParseTerm(rawTerm string) (string, bool) {
	trimmedTerm := strings.TrimSpace(rawTerm)
	if trimmedTerm == "" {
		return "", true
	}
	if !isAcceptableTerm(trimmedTerm) {
		return "", false
	}
	return trimmedTerm, true
}

func isAcceptableTerm(term string) bool {
	if !utf8.ValidString(term) {
		return false
	}
	termRuneCount := utf8.RuneCountInString(term)
	isWithinBounds := termRuneCount >= MinimumTermRunes && termRuneCount <= MaximumTermRunes
	return isWithinBounds && !strings.ContainsFunc(term, unicode.IsControl)
}

func ContainsPattern(term string) string {
	return "%" + likeMetacharacterEscaper.Replace(term) + "%"
}

func Matches(term string, candidateTexts ...string) bool {
	if term == "" {
		return true
	}
	loweredTerm := strings.ToLower(term)
	for _, candidateText := range candidateTexts {
		if strings.Contains(strings.ToLower(candidateText), loweredTerm) {
			return true
		}
	}
	return false
}
