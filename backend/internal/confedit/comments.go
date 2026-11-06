package confedit

import (
	"strconv"
	"strings"

	"crowdsec-dashboard/internal/confread"
)

const maxVerifiedComments = 32

func isCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

func isRealComment(parsed *parsedText, lineIndex int) bool {
	remainingLines := make([]string, 0, len(parsed.lines)-1)
	remainingLines = append(remainingLines, parsed.lines[:lineIndex]...)
	remainingLines = append(remainingLines, parsed.lines[lineIndex+1:]...)
	canonical, canonicalError := canonicalDocument(strings.Join(remainingLines, "\n"), canonicalizer{})
	return canonicalError == nil && canonical == parsed.canonical
}

func commentKeys(parsed *parsedText) map[int]string {
	keys := make(map[int]string)
	ordinals := make(map[string]int)
	enclosingIdentity := ""
	verifiedCount := 0
	for lineIndex, line := range parsed.lines {
		lineNumber := lineIndex + 1
		if slot, hasSlot := parsed.slots[lineNumber]; hasSlot {
			enclosingIdentity = slot.identity
			continue
		}
		if !isCommentLine(line) || !strings.Contains(line, confread.RedactedMarker) {
			continue
		}
		verifiedCount++
		if verifiedCount > maxVerifiedComments || !isRealComment(parsed, lineIndex) {
			continue
		}
		ordinals[enclosingIdentity]++
		keys[lineNumber] = enclosingIdentity + "\x00" + strconv.Itoa(ordinals[enclosingIdentity]) + "\x00" + line
	}
	return keys
}
