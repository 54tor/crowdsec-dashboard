package confedit

import (
	"fmt"
	"strings"

	"crowdsec-dashboard/internal/confread"
)

func firstMarkerLine(lines []string) int {
	for lineIndex, line := range lines {
		if strings.Contains(line, confread.RedactedMarker) {
			return lineIndex + 1
		}
	}
	return 0
}

func checkDestinationUnchanged(original, submitted *parsedText) error {
	if findIndirectionChange(original, submitted) {
		return &MergeError{Line: firstMarkerLine(submitted.lines), Err: ErrSecretContextChanged}
	}
	changedLine, hasChange := findEndpointChange(original, submitted)
	if !hasChange {
		return nil
	}
	if changedLine == 0 {
		changedLine = firstMarkerLine(submitted.lines)
	}
	return &MergeError{Line: changedLine, Err: ErrSecretContextChanged}
}

func MergeRedactedValues(originalRaw, submittedMasked []byte) ([]byte, error) {
	originalText, originalStyle := normaliseText(originalRaw)
	submittedText, _ := normaliseText(submittedMasked)
	if !strings.Contains(submittedText, confread.RedactedMarker) {
		return []byte(applyTextStyle(submittedText, originalStyle)), nil
	}

	original, originalError := loadOriginal(originalText)
	if originalError != nil {
		return nil, originalError
	}
	submitted, submittedError := parseText(submittedText)
	if submittedError != nil {
		return nil, fmt.Errorf("parse submitted: %w", submittedError)
	}
	if guardError := checkDestinationUnchanged(original.parsed, submitted); guardError != nil {
		return nil, guardError
	}

	mergedText, restored, restoreError := restoreSecrets(original, submitted)
	if restoreError != nil {
		return nil, restoreError
	}
	if verifyError := verifyMerged(mergedText, submittedText, restored); verifyError != nil {
		return nil, &MergeError{Line: firstMarkerLine(submitted.lines), Err: verifyError}
	}
	return []byte(applyTextStyle(mergedText, originalStyle)), nil
}

func restoreSecrets(original *originalDocument, submitted *parsedText) (string, []restoredSecret, error) {
	commentKeyByLine := commentKeys(submitted)
	mergedLines := make([]string, 0, len(submitted.lines))
	var restored []restoredSecret
	nextMergedLine := 1

	for lineIndex, submittedLine := range submitted.lines {
		lineNumber := lineIndex + 1
		if !strings.Contains(submittedLine, confread.RedactedMarker) {
			mergedLines = append(mergedLines, submittedLine)
			nextMergedLine++
			continue
		}

		lookupKey, isComment := commentKeyByLine[lineNumber]
		slot, hasSlot := submitted.slots[lineNumber]
		if !isComment {
			if !hasSlot {
				return "", nil, &MergeError{Line: lineNumber, Err: ErrRedactedWithoutOriginal}
			}
			lookupKey = secretKey(slot.identity, submittedLine)
		}

		secret, found := original.take(lookupKey)
		if !found {
			return "", nil, &MergeError{Line: lineNumber, Err: ErrRedactedWithoutOriginal}
		}
		if !isComment && secret.flowContainer != slot.flowContainer {
			return "", nil, &MergeError{Line: lineNumber, Err: ErrSecretContextChanged}
		}
		if !isComment {
			if !secret.hasValue {
				return "", nil, &MergeError{Line: lineNumber, Err: ErrMergedStructureChanged}
			}
			restored = append(restored, restoredSecret{
				mergedLine:     nextMergedLine,
				submittedLine:  lineNumber,
				originalValue:  secret.value,
				checksOriginal: true,
			})
		}
		mergedLines = append(mergedLines, secret.text)
		nextMergedLine += strings.Count(secret.text, "\n") + 1
	}
	return strings.Join(mergedLines, "\n"), restored, nil
}
