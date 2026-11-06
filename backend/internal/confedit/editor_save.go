package confedit

import (
	"context"
	"crypto/subtle"
	"sync"

	"crowdsec-dashboard/internal/confschema"
	"crowdsec-dashboard/internal/confwrite"
)

var saveMutex sync.Mutex

func (editor dirEditor) Save(ctx context.Context, request SaveRequest) (SaveResult, error) {
	if request.Name == readOnlyConfigName {
		return SaveResult{}, confwrite.ErrReadOnlyFile
	}
	if !request.Delete && len(request.Content) > confwrite.MaxFileBytes {
		return SaveResult{}, confwrite.ErrTooLarge
	}
	saveMutex.Lock()
	defer saveMutex.Unlock()
	current, readError := editor.readRaw(request.Name)
	if readError != nil {
		return SaveResult{}, readError
	}
	previousDigest := editor.digestOf(current)
	if !digestsMatch(previousDigest, request.ExpectedDigest) {
		return SaveResult{}, ErrDigestMismatch
	}
	change, changeError := buildChange(request, current)
	if changeError != nil {
		return SaveResult{}, changeError
	}
	return editor.apply(ctx, change, current, previousDigest)
}

func digestsMatch(currentDigest, expectedDigest string) bool {
	return subtle.ConstantTimeCompare([]byte(currentDigest), []byte(expectedDigest)) == 1
}

func buildChange(request SaveRequest, current confwrite.Current) (confwrite.FileChange, error) {
	if request.Delete {
		return confwrite.FileChange{Name: request.Name, Delete: true}, nil
	}
	merged, mergeError := MergeRedactedValues(current.Content, request.Content)
	if mergeError != nil {
		return confwrite.FileChange{}, mergeError
	}
	if hasBlockingIssue(confschema.Validate(request.Name, merged)) {
		return confwrite.FileChange{}, ErrSchemaInvalid
	}
	return confwrite.FileChange{Name: request.Name, Content: merged}, nil
}

func (editor dirEditor) apply(ctx context.Context, change confwrite.FileChange, current confwrite.Current, previousDigest string) (SaveResult, error) {
	configTestWithCallerContext := func(context.Context) error { return editor.configTest(ctx) }
	applyResult, applyError := confwrite.ApplyTree(editor.confDir, []confwrite.FileChange{change}, configTestWithCallerContext)
	saveResult := SaveResult{
		Created:        len(applyResult.Created) > 0,
		Deleted:        len(applyResult.Deleted) > 0,
		PreviousMasked: maskedContentOf(current),
		RolledBack:     applyResult.RolledBack,
		Digest:         previousDigest,
	}
	if applyError != nil {
		return saveResult, applyError
	}
	saveResult.Digest = editor.digestAfter(change)
	return saveResult, nil
}

func (editor dirEditor) digestAfter(change confwrite.FileChange) string {
	if change.Delete {
		return AbsentDigest
	}
	return editor.digester.Of(change.Content)
}
