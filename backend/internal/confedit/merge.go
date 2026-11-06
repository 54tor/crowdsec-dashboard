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
	keepChompingPattern       = regexp.MustCompile(`[ \t][|>][0-9]*\+[0-9]*(?:[ \t]+#.*)?$`)
)

type originalSecret struct {
	text    string
	context map[string]string
}

func secretKey(identity, maskedLine string) string {
	return identity + "\x00" + maskedLine
}

func restorableText(redactedLine confread.RedactedLine) string {
	firstLine, _, _ := strings.Cut(redactedLine.Original, "\n")
	if keepChompingPattern.MatchString(firstLine) {
		return redactedLine.Original
	}
	return trailingBlankLinesPattern.ReplaceAllString(redactedLine.Original, "")
}

func collectOriginalSecrets(originalText string) (map[string][]originalSecret, *parsedText, error) {
	redactedLines := confread.RedactLines([]byte(originalText))
	maskedLines := make([]string, 0, len(redactedLines))
	for _, redactedLine := range redactedLines {
		maskedLines = append(maskedLines, redactedLine.Masked)
	}
	parsed, parseError := parseText(strings.Join(maskedLines, "\n"))
	if parseError != nil {
		return nil, nil, fmt.Errorf("parse original: %w", parseError)
	}
	commentKeyByLine := commentKeys(parsed)

	secretsByKey := make(map[string][]originalSecret)
	for lineIndex, redactedLine := range redactedLines {
		if !strings.Contains(redactedLine.Masked, confread.RedactedMarker) {
			continue
		}
		lineNumber := lineIndex + 1
		if commentKey, isComment := commentKeyByLine[lineNumber]; isComment {
			secretsByKey[commentKey] = append(secretsByKey[commentKey], originalSecret{text: redactedLine.Original})
			continue
		}
		slot, hasSlot := parsed.slots[lineNumber]
		if !hasSlot {
			continue
		}
		key := secretKey(slot.identity, redactedLine.Masked)
		secretsByKey[key] = append(secretsByKey[key], originalSecret{text: restorableText(redactedLine), context: slot.context})
	}
	return secretsByKey, parsed, nil
}

func takeSecret(secretsByKey map[string][]originalSecret, key string) (originalSecret, bool) {
	candidates := secretsByKey[key]
	if len(candidates) == 0 {
		return originalSecret{}, false
	}
	secretsByKey[key] = candidates[1:]
	return candidates[0], true
}

func firstMarkerLine(lines []string) int {
	for lineIndex, line := range lines {
		if strings.Contains(line, confread.RedactedMarker) {
			return lineIndex + 1
		}
	}
	return 0
}

func MergeRedactedValues(originalRaw, submittedMasked []byte) ([]byte, error) {
	originalText, originalStyle := normaliseText(originalRaw)
	submittedText, _ := normaliseText(submittedMasked)
	if !strings.Contains(submittedText, confread.RedactedMarker) {
		return []byte(applyTextStyle(submittedText, originalStyle)), nil
	}

	secretsByKey, originalParsed, originalError := collectOriginalSecrets(originalText)
	if originalError != nil {
		return nil, originalError
	}
	submittedParsed, submittedError := parseText(submittedText)
	if submittedError != nil {
		return nil, fmt.Errorf("parse submitted: %w", submittedError)
	}
	if submittedParsed.usesIndirection && !originalParsed.usesIndirection {
		return nil, &MergeError{Line: firstMarkerLine(submittedParsed.lines), Err: ErrSecretContextChanged}
	}

	commentKeyByLine := commentKeys(submittedParsed)
	mergedLines := make([]string, 0, len(submittedParsed.lines))
	for lineIndex, submittedLine := range submittedParsed.lines {
		if !strings.Contains(submittedLine, confread.RedactedMarker) {
			mergedLines = append(mergedLines, submittedLine)
			continue
		}
		lineNumber := lineIndex + 1

		lookupKey, isComment := commentKeyByLine[lineNumber]
		var slotContext map[string]string
		if !isComment {
			slot, hasSlot := submittedParsed.slots[lineNumber]
			if !hasSlot {
				return nil, &MergeError{Line: lineNumber, Err: ErrRedactedWithoutOriginal}
			}
			lookupKey = secretKey(slot.identity, submittedLine)
			slotContext = slot.context
		}

		secret, found := takeSecret(secretsByKey, lookupKey)
		if !found {
			return nil, &MergeError{Line: lineNumber, Err: ErrRedactedWithoutOriginal}
		}
		if !isComment && !maps.Equal(secret.context, slotContext) {
			return nil, &MergeError{Line: lineNumber, Err: ErrSecretContextChanged}
		}
		mergedLines = append(mergedLines, secret.text)
	}
	return []byte(applyTextStyle(strings.Join(mergedLines, "\n"), originalStyle)), nil
}
