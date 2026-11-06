package logtail

import (
	"errors"
	"io/fs"
	"unicode/utf8"
)

const (
	DefaultLines     = 100
	MaxLines         = 500
	MaxLineBytes     = 4096
	MaxResponseBytes = 1 << 20
	truncationMarker = "…[truncated]"
)

var (
	ErrSourceNotFound   = errors.New("logtail: source not found")
	ErrSourceUnreadable = errors.New("logtail: source unreadable")
)

type Lines struct {
	Lines     []string
	FileSize  int64
	Truncated bool
}

type Reader struct {
	ConfDir      string
	AllowedRoots []string
}

func (reader Reader) List() (Listing, error) {
	return ListSources(reader.ConfDir, reader.AllowedRoots)
}

func (reader Reader) Read(sourceID string, lineCount int) (Lines, error) {
	listing, listError := reader.List()
	if listError != nil {
		return Lines{}, listError
	}
	source, isKnown := findSource(listing.Sources, sourceID)
	if !isKnown {
		return Lines{}, ErrSourceNotFound
	}
	tail, tailError := tailFile(source.Path, boundedLineCount(lineCount))
	if errors.Is(tailError, fs.ErrNotExist) {
		return Lines{}, ErrSourceNotFound
	}
	if tailError != nil {
		return Lines{}, ErrSourceUnreadable
	}
	return safeLines(tail), nil
}

func findSource(sources []Source, sourceID string) (Source, bool) {
	for _, sourceCourante := range sources {
		if sourceCourante.ID == sourceID {
			return sourceCourante, true
		}
	}
	return Source{}, false
}

func boundedLineCount(requested int) int {
	if requested <= 0 {
		return DefaultLines
	}
	return min(requested, MaxLines)
}

func safeLines(tail tailResult) Lines {
	result := Lines{Lines: make([]string, 0, len(tail.Lines)), FileSize: tail.FileSize}
	for _, ligneCourante := range tail.Lines {
		masked := MaskLine(ligneCourante)
		bounded, wasCut := truncateLine(masked)
		result.Truncated = result.Truncated || wasCut
		result.Lines = append(result.Lines, bounded)
	}
	return dropOldestOverBudget(result)
}

func truncateLine(line string) (string, bool) {
	if len(line) <= MaxLineBytes {
		return line, false
	}
	cut := MaxLineBytes
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + truncationMarker, true
}

func dropOldestOverBudget(result Lines) Lines {
	totalBytes := 0
	for _, ligneCourante := range result.Lines {
		totalBytes += len(ligneCourante) + 1
	}
	for totalBytes > MaxResponseBytes && len(result.Lines) > 0 {
		totalBytes -= len(result.Lines[0]) + 1
		result.Lines = result.Lines[1:]
		result.Truncated = true
	}
	return result
}
