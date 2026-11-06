package confedit

import "strings"

const byteOrderMark = "\xef\xbb\xbf"

type textStyle struct {
	hasByteOrderMark bool
	usesCrlf         bool
}

func normaliseText(raw []byte) (string, textStyle) {
	text := string(raw)
	style := textStyle{
		hasByteOrderMark: strings.HasPrefix(text, byteOrderMark),
		usesCrlf:         strings.Contains(text, "\r\n"),
	}
	text = strings.TrimPrefix(text, byteOrderMark)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return text, style
}

func applyTextStyle(text string, style textStyle) string {
	if style.usesCrlf {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	if style.hasByteOrderMark {
		text = byteOrderMark + text
	}
	return text
}
