package confedit

import (
	"strconv"
	"strings"
)

func isCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

func commentKeys(parsed *parsedText) map[int]string {
	keys := make(map[int]string)
	ordinals := make(map[string]int)
	enclosingIdentity := ""
	for lineIndex, line := range parsed.lines {
		lineNumber := lineIndex + 1
		if slot, hasSlot := parsed.slots[lineNumber]; hasSlot {
			enclosingIdentity = slot.identity
			continue
		}
		if parsed.blockLines[lineNumber] || !isCommentLine(line) {
			continue
		}
		ordinals[enclosingIdentity]++
		keys[lineNumber] = enclosingIdentity + "\x00" + strconv.Itoa(ordinals[enclosingIdentity]) + "\x00" + line
	}
	return keys
}
