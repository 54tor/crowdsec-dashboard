package logtail

import "regexp"

const redactedMarker = "[REDACTED]"

var maskingRules = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)((?:set-cookie|cookie|authorization)[ \t]*:[ \t]*).*$`), "${1}" + redactedMarker},
	{regexp.MustCompile(`(?i)(bearer[ \t]+)[^\s"',}]+`), "${1}" + redactedMarker},
	{regexp.MustCompile(`(?i)((?:password|passwd|token|api_key|apikey|secret)[ \t]*[=:][ \t]*)[^\s&"',;]+`), "${1}" + redactedMarker},
}

func MaskLine(line string) string {
	for _, ruleCourante := range maskingRules {
		line = ruleCourante.pattern.ReplaceAllString(line, ruleCourante.replacement)
	}
	return line
}
