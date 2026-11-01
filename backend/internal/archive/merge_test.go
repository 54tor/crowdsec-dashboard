package archive

import (
	"errors"
	"fmt"
	"testing"
)

// fakeArchive stands for the archive page reader: it serves a fixed slice through
// offset/limit, as ListAlerts does, and records every call it receives.
type fakeArchive struct {
	items      []string
	calledWith [][2]int
	failWith   error
}

func (archiveDouble *fakeArchive) page(offset int, limit int) ([]string, int, error) {
	archiveDouble.calledWith = append(archiveDouble.calledWith, [2]int{offset, limit})
	if archiveDouble.failWith != nil {
		return nil, 0, archiveDouble.failWith
	}
	if offset >= len(archiveDouble.items) {
		return []string{}, len(archiveDouble.items), nil
	}
	pageEnd := min(offset+limit, len(archiveDouble.items))
	return archiveDouble.items[offset:pageEnd], len(archiveDouble.items), nil
}

func labelledItems(prefix string, itemCount int) []string {
	items := make([]string, 0, itemCount)
	for itemNumber := 1; itemNumber <= itemCount; itemNumber++ {
		items = append(items, fmt.Sprintf("%s-%d", prefix, itemNumber))
	}
	return items
}

func TestMergePageOrdersFreshThenArchive(testContext *testing.T) {
	archiveDouble := &fakeArchive{items: labelledItems("archived", 3)}

	mergedItems, total, mergeError := MergePage(labelledItems("live", 2), archiveDouble.page, 1, 10)

	if mergeError != nil {
		testContext.Fatalf("merge: %v", mergeError)
	}
	expectedItems := []string{"live-1", "live-2", "archived-1", "archived-2", "archived-3"}
	if fmt.Sprint(mergedItems) != fmt.Sprint(expectedItems) {
		testContext.Errorf("expected %v, got %v", expectedItems, mergedItems)
	}
	if total != 5 {
		testContext.Errorf("total must be live + archive = 5, got %d", total)
	}
	if fmt.Sprint(archiveDouble.calledWith) != "[[0 8]]" {
		testContext.Errorf("archive must be asked for the 8 remaining slots from offset 0, got %v", archiveDouble.calledWith)
	}
}

func TestMergePageOffsetsArchiveAcrossPages(testContext *testing.T) {
	liveItems := labelledItems("live", 5)
	archiveDouble := &fakeArchive{items: labelledItems("archived", 120)}
	seenItems := map[string]int{}
	var orderedItems []string

	for pageNumber := 1; pageNumber <= 3; pageNumber++ {
		pageItems, total, mergeError := MergePage(liveItems, archiveDouble.page, pageNumber, 50)
		if mergeError != nil {
			testContext.Fatalf("page %d: %v", pageNumber, mergeError)
		}
		if total != 125 {
			testContext.Errorf("page %d: total must stay 125, got %d", pageNumber, total)
		}
		expectedLength := 50
		if pageNumber == 3 {
			expectedLength = 25
		}
		if len(pageItems) != expectedLength {
			testContext.Errorf("page %d: expected %d items, got %d", pageNumber, expectedLength, len(pageItems))
		}
		for _, pageItem := range pageItems {
			seenItems[pageItem]++
			orderedItems = append(orderedItems, pageItem)
		}
	}

	expectedOrder := append(labelledItems("live", 5), labelledItems("archived", 120)...)
	if fmt.Sprint(orderedItems) != fmt.Sprint(expectedOrder) {
		testContext.Errorf("pages 1-3 concatenated must be live then archive with no gap, got %v", orderedItems)
	}
	for seenItem, seenCount := range seenItems {
		if seenCount != 1 {
			testContext.Errorf("%s served %d times", seenItem, seenCount)
		}
	}
	if fmt.Sprint(archiveDouble.calledWith) != "[[0 45] [45 50] [95 50]]" {
		testContext.Errorf("archive offsets must be shifted by the 5 live items, got %v", archiveDouble.calledWith)
	}
}

func TestMergePagePastEndIsEmpty(testContext *testing.T) {
	archiveDouble := &fakeArchive{items: labelledItems("archived", 10)}

	pageItems, total, mergeError := MergePage(labelledItems("live", 3), archiveDouble.page, 5, 50)

	if mergeError != nil {
		testContext.Fatalf("merge: %v", mergeError)
	}
	if len(pageItems) != 0 {
		testContext.Errorf("a page past the end must be empty, got %v", pageItems)
	}
	if pageItems == nil {
		testContext.Errorf("an empty page must be a non-nil slice so it encodes as []")
	}
	if total != 13 {
		testContext.Errorf("the total must still be reported, got %d", total)
	}
}

func TestMergePageSkipsLiveItemsOfEarlierPages(testContext *testing.T) {
	archiveDouble := &fakeArchive{items: labelledItems("archived", 10)}

	pageItems, _, mergeError := MergePage(labelledItems("live", 7), archiveDouble.page, 2, 5)

	if mergeError != nil {
		testContext.Fatalf("merge: %v", mergeError)
	}
	expectedItems := []string{"live-6", "live-7", "archived-1", "archived-2", "archived-3"}
	if fmt.Sprint(pageItems) != fmt.Sprint(expectedItems) {
		testContext.Errorf("expected %v, got %v", expectedItems, pageItems)
	}
}

func TestMergePageReturnsArchiveError(testContext *testing.T) {
	archiveFailure := errors.New("archive unavailable")
	archiveDouble := &fakeArchive{failWith: archiveFailure}

	_, _, mergeError := MergePage(labelledItems("live", 2), archiveDouble.page, 1, 10)

	if !errors.Is(mergeError, archiveFailure) {
		testContext.Errorf("the archive error must be returned, got %v", mergeError)
	}
}

func TestMergePageRejectsInvalidPagination(testContext *testing.T) {
	archiveDouble := &fakeArchive{items: labelledItems("archived", 3)}

	for _, invalidPagination := range [][2]int{{0, 10}, {1, 0}, {-1, 10}, {1, -5}, {1, MaxQueryLimit + 1}, {1, 200}} {
		_, _, mergeError := MergePage(labelledItems("live", 2), archiveDouble.page, invalidPagination[0], invalidPagination[1])
		if !errors.Is(mergeError, ErrInvalidPagination) {
			testContext.Errorf("page %d per_page %d must be refused, got %v", invalidPagination[0], invalidPagination[1], mergeError)
		}
	}
	if len(archiveDouble.calledWith) != 0 {
		testContext.Errorf("a refused page must not reach the archive, got calls %v", archiveDouble.calledWith)
	}
}
