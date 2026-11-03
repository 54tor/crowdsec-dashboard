package bundle

import (
	"strings"

	"github.com/kylelemons/godebug/diff"

	"crowdsec-dashboard/internal/confread"
)

const maxDiffLines = 200

func boundedDiff(currentContent, newContent []byte) (string, bool) {
	currentLines, currentTruncated := firstLines(confread.Redact(currentContent))
	newLines, newTruncated := firstLines(confread.Redact(newContent))
	diffLines := renderDiff(diff.DiffChunks(currentLines, newLines))
	isTruncated := currentTruncated || newTruncated || len(diffLines) > maxDiffLines
	if len(diffLines) > maxDiffLines {
		diffLines = diffLines[:maxDiffLines]
	}
	return strings.Join(diffLines, "\n"), isTruncated
}

func firstLines(content []byte) ([]string, bool) {
	if len(content) == 0 {
		return []string{}, false
	}
	lines := strings.SplitN(strings.TrimSuffix(string(content), "\n"), "\n", maxDiffLines+1)
	if len(lines) > maxDiffLines {
		return lines[:maxDiffLines], true
	}
	return lines, false
}

func renderDiff(chunks []diff.Chunk) []string {
	renderedLines := []string{}
	for _, chunk := range chunks {
		renderedLines = appendPrefixed(renderedLines, "+", chunk.Added)
		renderedLines = appendPrefixed(renderedLines, "-", chunk.Deleted)
		renderedLines = appendPrefixed(renderedLines, " ", chunk.Equal)
	}
	return renderedLines
}

func appendPrefixed(renderedLines []string, prefix string, lines []string) []string {
	for _, line := range lines {
		renderedLines = append(renderedLines, prefix+line)
	}
	return renderedLines
}
