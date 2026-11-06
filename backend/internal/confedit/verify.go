package confedit

import (
	"errors"
	"fmt"
)

var ErrMergedStructureChanged = errors.New("merged output differs structurally from the submitted text")

type restoredSecret struct {
	mergedLine     int
	submittedLine  int
	originalValue  string
	checksOriginal bool
}

func verifyMerged(mergedText, submittedText string, restored []restoredSecret) error {
	mergedLines := make(map[int]bool, len(restored))
	submittedLines := make(map[int]bool, len(restored))
	for _, secret := range restored {
		mergedLines[secret.mergedLine] = true
		submittedLines[secret.submittedLine] = true
	}

	mergedCanonical, mergedError := canonicalDocument(mergedText, canonicalizer{ignoredLines: mergedLines})
	if mergedError != nil {
		return fmt.Errorf("%w: %v", ErrMergedStructureChanged, mergedError)
	}
	submittedCanonical, submittedError := canonicalDocument(submittedText, canonicalizer{ignoredLines: submittedLines})
	if submittedError != nil || mergedCanonical != submittedCanonical {
		return ErrMergedStructureChanged
	}

	mergedParsed, parseError := parseText(mergedText)
	if parseError != nil {
		return ErrMergedStructureChanged
	}
	for _, secret := range restored {
		if !secret.checksOriginal {
			continue
		}
		slot, hasSlot := mergedParsed.slots[secret.mergedLine]
		if !hasSlot {
			return ErrMergedStructureChanged
		}
		mergedValue := canonicalizer{}.node(slot.value)
		if mergedValue != secret.originalValue {
			return ErrMergedStructureChanged
		}
	}
	return nil
}
