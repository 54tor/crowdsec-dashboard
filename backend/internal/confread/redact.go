package confread

import (
	"regexp"
	"strings"
)

const (
	RedactedMarker = "[REDACTED]"
	sensitiveNames = `password|passwd|token|secret|api_key|apikey|key|authorization|bearer|credential|dsn`
)

var (
	urlCredentialsPattern = regexp.MustCompile(`(://)[^/\s]*@`)
	bearerPattern         = regexp.MustCompile(`(?i)(bearer[ \t]+)[^\s"',}]+`)
	sensitiveLinePattern  = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?["']?[^\n:#"']*(?:` + sensitiveNames + `)[^\n:#"']*["']?[ \t]*:[ \t]*)(.*)$`)
	inlineEntryPattern    = regexp.MustCompile(`(?i)([{,][ \t]*["']?[^\s:,{}"']*(?:` + sensitiveNames + `)[^\s:,{}"']*["']?[ \t]*:[ \t]*)("[^"]*"|'[^']*'|[^,}]*)`)
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
	line = urlCredentialsPattern.ReplaceAllString(line, "${1}"+RedactedMarker+"@")
	line = bearerPattern.ReplaceAllString(line, "${1}"+RedactedMarker)
	match := sensitiveLinePattern.FindStringSubmatch(line)
	if match == nil {
		return inlineEntryPattern.ReplaceAllString(line, "${1}"+RedactedMarker), -1
	}
	return strings.TrimRight(match[1], " \t") + " " + RedactedMarker, keyIndent(match[1])
}

type RedactedLine struct {
	Masked   string
	Original string
}

func RedactLines(content []byte) []RedactedLine {
	lines := strings.Split(string(content), "\n")
	output := make([]RedactedLine, 0, len(lines))
	blockIndent := -1
	for _, line := range lines {
		if blockIndent >= 0 {
			if isMaskedContinuation(line, blockIndent) {
				lastIndex := len(output) - 1
				output[lastIndex].Original += "\n" + line
				continue
			}
			blockIndent = -1
		}
		redacted, openedBlock := redactLine(line)
		output = append(output, RedactedLine{Masked: redacted, Original: line})
		blockIndent = openedBlock
	}
	return output
}

func redactSecrets(content []byte) []byte {
	redactedLines := RedactLines(content)
	maskedLines := make([]string, 0, len(redactedLines))
	for _, redactedLine := range redactedLines {
		maskedLines = append(maskedLines, redactedLine.Masked)
	}
	return []byte(strings.Join(maskedLines, "\n"))
}

func Redact(content []byte) []byte {
	return redactSecrets(content)
}
