package confwrite

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
)

var (
	ErrConfigTestFailed   = errors.New("confwrite: config test failed")
	ErrConfigInconsistent = errors.New("confwrite: config inconsistent")
)

type Result struct {
	Created    []string
	Updated    []string
	Deleted    []string
	Unchanged  []string
	RolledBack bool
}

type InconsistentError struct {
	Files []string
}

func (inconsistentError *InconsistentError) Error() string {
	return ErrConfigInconsistent.Error()
}

func (inconsistentError *InconsistentError) Is(target error) bool {
	return target == ErrConfigInconsistent
}

var applyMutex sync.Mutex

type renameFunc func(root *os.Root, fromName, toName string) error

type fileSystemHooks struct {
	rename        renameFunc
	syncDirectory func(root *os.Root, name string) error
}

func defaultHooks() fileSystemHooks {
	return fileSystemHooks{rename: renameInRoot, syncDirectory: syncDirectory}
}

func renameInRoot(root *os.Root, fromName, toName string) error {
	return root.Rename(fromName, toName)
}

func Apply(rootDir string, changes []FileChange, test func(ctx context.Context) error) (Result, error) {
	return applyWith(rootDir, changes, test, defaultHooks())
}

func ApplyTree(rootDir string, changes []FileChange, test func(ctx context.Context) error) (Result, error) {
	return applyTreeWith(rootDir, changes, test, defaultHooks(), ValidateEditableName)
}

func applyWith(rootDir string, changes []FileChange, test func(ctx context.Context) error, hooks fileSystemHooks) (Result, error) {
	return applyTreeWith(rootDir, changes, test, hooks, ValidateName)
}

func applyTreeWith(rootDir string, changes []FileChange, test func(ctx context.Context) error, hooks fileSystemHooks, validateName func(string) error) (Result, error) {
	applyMutex.Lock()
	defer applyMutex.Unlock()
	if validationError := validateChanges(changes, validateName); validationError != nil {
		return Result{}, validationError
	}
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return Result{}, openError
	}
	defer root.Close()
	if pendingError := refusePendingRecovery(root); pendingError != nil {
		return Result{}, pendingError
	}
	writeTransaction := &transaction{root: root, hooks: hooks}
	result, classifyError := writeTransaction.classify(changes)
	if classifyError != nil || len(writeTransaction.writes) == 0 {
		return result, classifyError
	}
	if stageError := writeTransaction.stage(); stageError != nil {
		writeTransaction.abandonStage()
		return Result{}, stageError
	}
	if commitError := writeTransaction.commit(); commitError != nil {
		return writeTransaction.rollback(result, commitError)
	}
	if testError := test(context.Background()); testError != nil {
		return writeTransaction.rollback(result, ErrConfigTestFailed)
	}
	return writeTransaction.finish(result)
}

func refusePendingRecovery(root *os.Root) error {
	pendingDirs, listError := pendingJournalDirs(root)
	if listError != nil {
		return listError
	}
	if len(pendingDirs) > 0 {
		return ErrRecoveryPending
	}
	return nil
}

func HasPendingRecovery(rootDir string) (bool, error) {
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return false, openError
	}
	defer root.Close()
	pendingDirs, listError := pendingJournalDirs(root)
	return len(pendingDirs) > 0, listError
}

func sortedChanges(changes []FileChange) []FileChange {
	sorted := slices.Clone(changes)
	slices.SortFunc(sorted, func(first, second FileChange) int { return strings.Compare(first.Name, second.Name) })
	return sorted
}
