package archive

import "errors"

var ErrInvalidPagination = errors.New("archive: invalid pagination")

func MergePage[T any](fresh []T, archivePage func(offset, limit int) ([]T, int, error), page, perPage int) ([]T, int, error) {
	if page < 1 || perPage < 1 || perPage > MaxQueryLimit {
		return nil, 0, ErrInvalidPagination
	}
	pageStart := (page - 1) * perPage
	freshStart := min(pageStart, len(fresh))
	freshEnd := min(pageStart+perPage, len(fresh))
	mergedItems := make([]T, 0, perPage)
	mergedItems = append(mergedItems, fresh[freshStart:freshEnd]...)
	archiveOffset := max(0, pageStart-len(fresh))
	archiveItems, archiveTotal, archiveError := archivePage(archiveOffset, perPage-len(mergedItems))
	if archiveError != nil {
		return nil, 0, archiveError
	}
	mergedItems = append(mergedItems, archiveItems...)
	return mergedItems, len(fresh) + archiveTotal, nil
}
