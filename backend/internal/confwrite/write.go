package confwrite

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
)

var (
	ErrConfigTestFailed   = errors.New("confwrite: config test failed")
	ErrConfigInconsistent = errors.New("confwrite: config inconsistent")
)

type Result struct {
	Created    []string
	Updated    []string
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

type renameFunc func(root *os.Root, fromName, toName string) error

func renameInRoot(root *os.Root, fromName, toName string) error {
	return root.Rename(fromName, toName)
}

func Apply(rootDir string, changes []FileChange, test func(ctx context.Context) error) (Result, error) {
	return applyWith(rootDir, changes, test, renameInRoot)
}

func applyWith(rootDir string, changes []FileChange, test func(ctx context.Context) error, rename renameFunc) (Result, error) {
	if validationError := validateChanges(changes); validationError != nil {
		return Result{}, validationError
	}
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return Result{}, openError
	}
	defer root.Close()
	writeTransaction := &transaction{root: root, rename: rename}
	result, classifyError := writeTransaction.classify(changes)
	if classifyError != nil || len(writeTransaction.writes) == 0 {
		return result, classifyError
	}
	if stageError := writeTransaction.stage(); stageError != nil {
		writeTransaction.discardTemps()
		return Result{}, stageError
	}
	if commitError := writeTransaction.commit(); commitError != nil {
		return writeTransaction.rollback(result, commitError)
	}
	if testError := test(context.Background()); testError != nil {
		return writeTransaction.rollback(result, ErrConfigTestFailed)
	}
	return result, nil
}

func sortedChanges(changes []FileChange) []FileChange {
	sorted := slices.Clone(changes)
	slices.SortFunc(sorted, func(first, second FileChange) int { return strings.Compare(first.Name, second.Name) })
	return sorted
}
