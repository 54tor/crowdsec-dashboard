package confedit

import (
	"fmt"
	"maps"
	"regexp"
	"strings"

	"crowdsec-dashboard/internal/confread"
)

var (
	trailingBlankLinesPattern = regexp.MustCompile(`(\n[ \t]*)+$`)
	keepChompingPattern       = regexp.MustCompile(`:[ \t]*[|>][0-9+-]*\+`)
)

type originalSecret struct {
	text    string
	context map[string]string
}

func isCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

func secretKey(identity, maskedLine string) string {
	return identity + "\x00" + maskedLine
}

func commentKey(maskedLine string) string {
	return "#" + maskedLine
}

func restorableText(redactedLine confread.RedactedLine) string {
	firstLine, _, _ := strings.Cut(redactedLine.Original, "\n")
	if keepChompingPattern.MatchString(firstLine) {
		return redactedLine.Original
	}
	return trailingBlankLinesPattern.ReplaceAllString(redactedLine.Original, "")
}

func collectOriginalSecrets(originalText string) (map[string][]originalSecret, error) {
	redactedLines := confread.RedactLines([]byte(originalText))
	maskedLines := make([]string, 0, len(redactedLines))
	for _, redactedLine := range redactedLines {
		maskedLines = append(maskedLines, redactedLine.Masked)
	}
	slots, parseError := parseSecretSlots(strings.Join(maskedLines, "\n"))
	if parseError != nil {
		return nil, fmt.Errorf("parse original: %w", parseError)
	}

	secretsByKey := make(map[string][]originalSecret)
	for lineIndex, redactedLine := range redactedLines {
		if !strings.Contains(redactedLine.Masked, confread.RedactedMarker) {
			continue
		}
		if isCommentLine(redactedLine.Masked) {
			key := commentKey(redactedLine.Masked)
			secretsByKey[key] = append(secretsByKey[key], originalSecret{text: redactedLine.Original})
			continue
		}
		slot, hasSlot := slots[lineIndex+1]
		if !hasSlot {
			continue
		}
		key := secretKey(slot.identity, redactedLine.Masked)
		secretsByKey[key] = append(secretsByKey[key], originalSecret{text: restorableText(redactedLine), context: slot.context})
	}
	return secretsByKey, nil
}

func takeSecret(secretsByKey map[string][]originalSecret, key string) (originalSecret, bool) {
	candidates := secretsByKey[key]
	if len(candidates) == 0 {
		return originalSecret{}, false
	}
	secretsByKey[key] = candidates[1:]
	return candidates[0], true
}

func MergeRedactedValues(originalRaw, submittedMasked []byte) ([]byte, error) {
	if !strings.Contains(string(submittedMasked), confread.RedactedMarker) {
		return submittedMasked, nil
	}

	originalText, originalStyle := normaliseText(originalRaw)
	submittedText, _ := normaliseText(submittedMasked)

	secretsByKey, originalError := collectOriginalSecrets(originalText)
	if originalError != nil {
		return nil, originalError
	}
	submittedSlots, submittedError := parseSecretSlots(submittedText)
	if submittedError != nil {
		return nil, fmt.Errorf("parse submitted: %w", submittedError)
	}

	submittedLines := strings.Split(submittedText, "\n")
	mergedLines := make([]string, 0, len(submittedLines))
	for lineIndex, submittedLine := range submittedLines {
		if !strings.Contains(submittedLine, confread.RedactedMarker) {
			mergedLines = append(mergedLines, submittedLine)
			continue
		}
		lineNumber := lineIndex + 1

		if isCommentLine(submittedLine) {
			secret, found := takeSecret(secretsByKey, commentKey(submittedLine))
			if !found {
				secret.text = submittedLine
			}
			mergedLines = append(mergedLines, secret.text)
			continue
		}

		slot, hasSlot := submittedSlots[lineNumber]
		if !hasSlot {
			return nil, &MergeError{Line: lineNumber, Err: ErrRedactedWithoutOriginal}
		}
		secret, found := takeSecret(secretsByKey, secretKey(slot.identity, submittedLine))
		if !found {
			return nil, &MergeError{Line: lineNumber, Err: ErrRedactedWithoutOriginal}
		}
		if !maps.Equal(secret.context, slot.context) {
			return nil, &MergeError{Line: lineNumber, Err: ErrSecretContextChanged}
		}
		mergedLines = append(mergedLines, secret.text)
	}
	return []byte(applyTextStyle(strings.Join(mergedLines, "\n"), originalStyle)), nil
}
