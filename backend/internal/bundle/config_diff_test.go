package bundle

import (
	"strings"
	"testing"
)

// A sidecar sends the current file already redacted; boundedDiff redacts it
// again so a reader that forgot to mask can never put a secret in a preview.
func TestBoundedDiffMasksTheCurrentSideEvenWhenGivenRawContent(testContext *testing.T) {
	rawCurrentContent := []byte("source: file\npassword: hunter2\n")
	newContent := []byte("source: file\npassword: hunter3\nlabels: {type: nginx}\n")

	renderedDiff, _ := boundedDiff(rawCurrentContent, newContent)

	if strings.Contains(renderedDiff, "hunter2") || strings.Contains(renderedDiff, "hunter3") {
		testContext.Errorf("the diff leaked a secret:\n%s", renderedDiff)
	}
	if !strings.Contains(renderedDiff, "+labels: {type: nginx}") {
		testContext.Errorf("the diff must still show the real change:\n%s", renderedDiff)
	}
}
