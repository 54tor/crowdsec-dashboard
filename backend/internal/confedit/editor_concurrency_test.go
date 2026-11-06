package confedit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/confwrite"
)

// replaceApplyTree swaps the editor's ApplyTree seam for the duration of one
// test. It is the only way to land an external write in the window between the
// editor's own read (digest check, secret merge) and the transaction's re-read.
func replaceApplyTree(testContext *testing.T, replacement func(string, []confwrite.FileChange, func(context.Context) error) (confwrite.Result, error)) {
	testContext.Helper()
	originalApplyTree := applyTree
	applyTree = replacement
	testContext.Cleanup(func() { applyTree = originalApplyTree })
}

// The secret rotated by an external writer after the editor read the file must
// survive: the editor pins the raw content it merged against, ApplyTree sees
// the difference under its lock and the save is reported as a digest mismatch.
func TestSaveRefusesWhenFileChangesAfterDigestCheck(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, localOverrideName, localOverrideWithSecret)
	file := readForEdit(testContext, editor, localOverrideName)
	rotatedSecret := "db_config:\n  user: crowdsec\n  password: rotated\n"
	replaceApplyTree(testContext, func(rootDir string, changes []confwrite.FileChange, configTest func(context.Context) error) (confwrite.Result, error) {
		writeConfigFile(testContext, configDirectory, localOverrideName, rotatedSecret)
		return confwrite.ApplyTree(rootDir, changes, configTest)
	})

	_, saveError := editor.Save(context.Background(), SaveRequest{Name: localOverrideName, Content: file.Content, ExpectedDigest: file.Digest})

	if !errors.Is(saveError, ErrDigestMismatch) {
		testContext.Fatalf("got %v, want ErrDigestMismatch", saveError)
	}
	if readConfigFile(testContext, configDirectory, localOverrideName) != rotatedSecret {
		testContext.Fatal("the externally rotated secret was overwritten")
	}
}

// Same window for a creation: the editor saw the file absent, someone created
// it meanwhile, the creation must not replace it.
func TestSaveRefusesCreationWhenFileAppearsAfterDigestCheck(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	replaceApplyTree(testContext, func(rootDir string, changes []confwrite.FileChange, configTest func(context.Context) error) (confwrite.Result, error) {
		writeConfigFile(testContext, configDirectory, profilesName, "name: external\nfilters: []\n")
		return confwrite.ApplyTree(rootDir, changes, configTest)
	})

	_, saveError := editor.Save(context.Background(), SaveRequest{Name: profilesName, Content: []byte(validProfiles), ExpectedDigest: AbsentDigest})

	if !errors.Is(saveError, ErrDigestMismatch) {
		testContext.Fatalf("got %v, want ErrDigestMismatch", saveError)
	}
}

// A request already cancelled (client gone) must not reach the transaction.
func TestSaveReturnsContextErrorWhenAlreadyCancelled(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	_, saveError := editor.Save(cancelledContext, SaveRequest{Name: profilesName, Content: []byte(validProfiles), ExpectedDigest: AbsentDigest})

	if !errors.Is(saveError, context.Canceled) {
		testContext.Fatalf("got %v, want context.Canceled", saveError)
	}
	if readForEdit(testContext, editor, profilesName).Exists {
		testContext.Fatalf("a cancelled save created %s in %s", profilesName, configDirectory)
	}
}

// Two dashboard users saving the same version at once: the first wins, the
// second sees the new digest and is refused; neither blocks the other forever.
func TestConcurrentSavesWithSameDigestLetExactlyOneSucceed(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, validProfiles)
	file := readForEdit(testContext, editor, profilesName)
	submittedContents := []string{"name: first\nfilters:\n  - true\n", "name: second\nfilters:\n  - true\n"}
	saveErrors := make([]error, len(submittedContents))
	var waitGroup sync.WaitGroup
	for saveIndex, submittedContent := range submittedContents {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, saveErrors[saveIndex] = editor.Save(context.Background(), SaveRequest{Name: profilesName, Content: []byte(submittedContent), ExpectedDigest: file.Digest})
		}()
	}
	finished := make(chan struct{})
	go func() { waitGroup.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		testContext.Fatal("concurrent saves deadlocked")
	}

	successCount, mismatchCount := 0, 0
	for _, saveError := range saveErrors {
		switch {
		case saveError == nil:
			successCount++
		case errors.Is(saveError, ErrDigestMismatch):
			mismatchCount++
		default:
			testContext.Errorf("unexpected error %v", saveError)
		}
	}
	if successCount != 1 || mismatchCount != 1 {
		testContext.Fatalf("successes=%d mismatches=%d, want 1 and 1", successCount, mismatchCount)
	}
}
