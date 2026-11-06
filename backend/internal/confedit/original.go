package confedit

import (
	"fmt"
	"regexp"
	"strings"

	"crowdsec-dashboard/internal/confread"
)

var (
	trailingBlankLinesPattern = regexp.MustCompile(`(\n[ \t]*)+$`)
	keepChompingPattern       = regexp.MustCompile(`[ \t][|>][0-9]*\+[0-9]*(?:[ \t]+#.*)?$`)
)

type originalSecret struct {
	text          string
	flowContainer bool
	value         string
	hasValue      bool
	isComment     bool
}

type originalDocument struct {
	secretsByKey map[string][]originalSecret
	parsed       *parsedText
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

func loadOriginal(originalText string) (*originalDocument, error) {
	redactedLines := confread.RedactLines([]byte(originalText))
	maskedLines := make([]string, 0, len(redactedLines))
	for _, redactedLine := range redactedLines {
		maskedLines = append(maskedLines, redactedLine.Masked)
	}
	maskedParsed, maskedError := parseText(strings.Join(maskedLines, "\n"))
	if maskedError != nil {
		return nil, fmt.Errorf("parse original: %w", maskedError)
	}
	rawParsed, rawError := parseText(originalText)
	if rawError != nil {
		return nil, fmt.Errorf("parse original: %w", rawError)
	}
	commentKeyByLine := commentKeys(maskedParsed)

	secretsByKey := make(map[string][]originalSecret)
	rawLineNumber := 1
	for lineIndex, redactedLine := range redactedLines {
		currentRawLine := rawLineNumber
		rawLineNumber += strings.Count(redactedLine.Original, "\n") + 1
		if !strings.Contains(redactedLine.Masked, confread.RedactedMarker) {
			continue
		}
		lineNumber := lineIndex + 1
		if commentKey, isComment := commentKeyByLine[lineNumber]; isComment {
			secretsByKey[commentKey] = append(secretsByKey[commentKey], originalSecret{text: redactedLine.Original, isComment: true})
			continue
		}
		slot, hasSlot := maskedParsed.slots[lineNumber]
		if !hasSlot {
			continue
		}
		secret := originalSecret{text: restorableText(redactedLine), flowContainer: slot.flowContainer}
		if rawSlot, hasRawSlot := rawParsed.slots[currentRawLine]; hasRawSlot {
			secret.value = rawParsed.plain.node(rawSlot.value)
			secret.hasValue = true
		}
		key := secretKey(slot.identity, redactedLine.Masked)
		secretsByKey[key] = append(secretsByKey[key], secret)
	}
	return &originalDocument{secretsByKey: secretsByKey, parsed: maskedParsed}, nil
}

func (document *originalDocument) take(key string) (originalSecret, bool) {
	candidates := document.secretsByKey[key]
	if len(candidates) == 0 {
		return originalSecret{}, false
	}
	document.secretsByKey[key] = candidates[1:]
	return candidates[0], true
}
