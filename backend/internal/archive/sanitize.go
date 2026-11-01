package archive

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"crowdsec-dashboard/internal/lapi"
)

type Bounds struct {
	MaxEventsPerAlert    int
	MaxDecisionsPerAlert int
	MaxMetaKeys          int
	MaxMetaKeyBytes      int
	MaxMetaValueBytes    int
	MaxMetaEncodedBytes  int
	MaxTextBytes         int
	MaxMessageBytes      int
}

var DefaultBounds = Bounds{
	MaxEventsPerAlert:    200,
	MaxDecisionsPerAlert: 200,
	MaxMetaKeys:          64,
	MaxMetaKeyBytes:      128,
	MaxMetaValueBytes:    4096,
	MaxMetaEncodedBytes:  61440,
	MaxTextBytes:         512,
	MaxMessageBytes:      4096,
}

const emptyObjectEncodedBytes = len("{}")

func SanitizeText(raw string, maxBytes int) string {
	sanitizedText, _ := sanitizeTextReportingCut(raw, maxBytes)
	return sanitizedText
}

func sanitizeTextReportingCut(raw string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		return "", raw != ""
	}
	cleanedText := strings.ReplaceAll(strings.ToValidUTF8(raw, "�"), "\x00", "")
	if len(cleanedText) <= maxBytes {
		return cleanedText, false
	}
	cutIndex := maxBytes
	for cutIndex > 0 && !utf8.RuneStart(cleanedText[cutIndex]) {
		cutIndex--
	}
	return cleanedText[:cutIndex], true
}

func EventMeta(entries []lapi.MetaEntry, bounds Bounds) (map[string]string, bool) {
	meta := map[string]string{}
	truncated := false
	encodedBytes := emptyObjectEncodedBytes
	for _, entry := range entries {
		key, keyCut := sanitizeTextReportingCut(entry.Key, bounds.MaxMetaKeyBytes)
		if _, alreadyPresent := meta[key]; alreadyPresent {
			continue
		}
		value, valueCut := sanitizeTextReportingCut(entry.Value, bounds.MaxMetaValueBytes)
		entryBytes := encodedStringBytes(key) + len(":") + encodedStringBytes(value)
		if len(meta) > 0 {
			entryBytes += len(",")
		}
		if len(meta) >= bounds.MaxMetaKeys || encodedBytes+entryBytes > bounds.MaxMetaEncodedBytes {
			return meta, true
		}
		meta[key] = value
		encodedBytes += entryBytes
		truncated = truncated || keyCut || valueCut
	}
	return meta, truncated
}

func encodedStringBytes(text string) int {
	encodedText, _ := json.Marshal(text)
	return len(encodedText)
}
