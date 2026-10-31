package confread

import (
	"regexp"
	"strings"
)

const (
	redactedMarker  = "[REDACTED]"
	sensitiveNames  = `password|passwd|token|secret|api_key|apikey|key|authorization|bearer|credential|dsn`
	blockIndicators = `^[|>][+-]?[0-9]?[+-]?$`
)

var (
	urlCredentialsPattern = regexp.MustCompile(`(://)[^/\s:@]*:[^/\s@]*@`)
	bearerPattern         = regexp.MustCompile(`(?i)(bearer[ \t]+)[^\s"',}]+`)
	sensitiveLinePattern  = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?["']?[^\n:#"']*(?:` + sensitiveNames + `)[^\n:#"']*["']?[ \t]*:[ \t]*)(.*)$`)
	inlineEntryPattern    = regexp.MustCompile(`(?i)([{,][ \t]*["']?[^\s:,{}"']*(?:` + sensitiveNames + `)[^\s:,{}"']*["']?[ \t]*:[ \t]*)("[^"]*"|'[^']*'|[^,}]*)`)
	blockIndicatorPattern = regexp.MustCompile(blockIndicators)
)

func leadingIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

func keyIndent(prefix string) int {
	indent := leadingIndent(prefix)
	if strings.HasPrefix(strings.TrimLeft(prefix, " \t"), "-") {
		return indent + 2
	}
	return indent
}

func isMaskedContinuation(line string, blockIndent int) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	indent := leadingIndent(line)
	return indent > blockIndent || (indent == blockIndent && strings.HasPrefix(trimmed, "- "))
}

func redactLine(line string) (redacted string, blockIndent int) {
	line = urlCredentialsPattern.ReplaceAllString(line, "${1}"+redactedMarker+"@")
	line = bearerPattern.ReplaceAllString(line, "${1}"+redactedMarker)
	match := sensitiveLinePattern.FindStringSubmatch(line)
	if match == nil {
		return inlineEntryPattern.ReplaceAllString(line, "${1}"+redactedMarker), -1
	}
	value := strings.TrimSpace(match[2])
	if value == "" || blockIndicatorPattern.MatchString(value) {
		return line, keyIndent(match[1])
	}
	return match[1] + redactedMarker, -1
}

func redactSecrets(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	output := make([]string, 0, len(lines))
	blockIndent := -1
	for _, line := range lines {
		if blockIndent >= 0 {
			if isMaskedContinuation(line, blockIndent) {
				continue
			}
			blockIndent = -1
		}
		redacted, openedBlock := redactLine(line)
		output = append(output, redacted)
		if openedBlock >= 0 {
			output = append(output, strings.Repeat(" ", openedBlock+2)+redactedMarker)
			blockIndent = openedBlock
		}
	}
	return []byte(strings.Join(output, "\n"))
}
