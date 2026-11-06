package confedit

import (
	"errors"
	"regexp"
	"strings"

	"crowdsec-dashboard/internal/confread"
)

var ErrRedactedWithoutOriginal = errors.New("redacted marker has no original secret at this position")

var trailingBlankLinesPattern = regexp.MustCompile(`(\n[ \t]*)+$`)

type parentKey struct {
	indent int
	name   string
}

func leadingIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

func parentPaths(lines []string) []string {
	paths := make([]string, len(lines))
	var parents []parentKey
	for lineIndex, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := leadingIndent(line)
		for len(parents) > 0 && parents[len(parents)-1].indent >= indent {
			parents = parents[:len(parents)-1]
		}
		names := make([]string, 0, len(parents))
		for _, parent := range parents {
			names = append(names, parent.name)
		}
		paths[lineIndex] = strings.Join(names, "/")
		if strings.HasSuffix(trimmed, ":") {
			parents = append(parents, parentKey{indent: indent, name: trimmed})
		}
	}
	return paths
}

func secretKey(path, maskedLine string) string {
	return path + "\x00" + maskedLine
}

func originalSecretsByKey(originalRaw []byte) map[string][]string {
	redactedLines := confread.RedactLines(originalRaw)
	maskedLines := make([]string, 0, len(redactedLines))
	for _, redactedLine := range redactedLines {
		maskedLines = append(maskedLines, redactedLine.Masked)
	}
	paths := parentPaths(maskedLines)

	secretsByKey := make(map[string][]string)
	for lineIndex, redactedLine := range redactedLines {
		if !strings.Contains(redactedLine.Masked, confread.RedactedMarker) {
			continue
		}
		key := secretKey(paths[lineIndex], redactedLine.Masked)
		originalWithoutTrailingBlankLines := trailingBlankLinesPattern.ReplaceAllString(redactedLine.Original, "")
		secretsByKey[key] = append(secretsByKey[key], originalWithoutTrailingBlankLines)
	}
	return secretsByKey
}

func MergeRedactedValues(originalRaw, submittedMasked []byte) ([]byte, error) {
	secretsByKey := originalSecretsByKey(originalRaw)
	submittedLines := strings.Split(string(submittedMasked), "\n")
	paths := parentPaths(submittedLines)

	mergedLines := make([]string, 0, len(submittedLines))
	for lineIndex, submittedLine := range submittedLines {
		if !strings.Contains(submittedLine, confread.RedactedMarker) {
			mergedLines = append(mergedLines, submittedLine)
			continue
		}
		key := secretKey(paths[lineIndex], submittedLine)
		candidates := secretsByKey[key]
		if len(candidates) == 0 {
			return nil, ErrRedactedWithoutOriginal
		}
		mergedLines = append(mergedLines, candidates[0])
		secretsByKey[key] = candidates[1:]
	}
	return []byte(strings.Join(mergedLines, "\n")), nil
}
