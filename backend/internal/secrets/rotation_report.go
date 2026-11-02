package secrets

import (
	"errors"
	"fmt"
	"strings"
)

var ErrUnreadableRows = errors.New("rows cannot be opened with their associated data")

type ColumnReport struct {
	Column            string
	KeyIDCounts       map[string]int64
	Rewritten         int64
	SkippedConcurrent int64
	UnreadableIDs     []int64
}

type RotationReport struct {
	CurrentKeyID string
	Columns      []ColumnReport
}

func (report RotationReport) Rewritten() int64 {
	var rewrittenTotal int64
	for _, columnReport := range report.Columns {
		rewrittenTotal += columnReport.Rewritten
	}
	return rewrittenTotal
}

func (report RotationReport) unreadableError() error {
	var unreadableColumns []string
	for _, columnReport := range report.Columns {
		if len(columnReport.UnreadableIDs) > 0 {
			unreadableColumns = append(unreadableColumns, fmt.Sprintf("%s row ids %v", columnReport.Column, columnReport.UnreadableIDs))
		}
	}
	if len(unreadableColumns) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnreadableRows, strings.Join(unreadableColumns, "; "))
}
