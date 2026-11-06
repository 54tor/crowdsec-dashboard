package confedit

import (
	"errors"
	"fmt"
)

var (
	ErrRedactedWithoutOriginal = errors.New("redacted marker has no original secret at this position")
	ErrSecretContextChanged    = errors.New("secret cannot be restored because its sibling url or host changed")
	ErrNestingTooDeep          = errors.New("yaml nesting exceeds the supported depth")
)

type MergeError struct {
	Line int
	Err  error
}

func (mergeError *MergeError) Error() string {
	return fmt.Sprintf("line %d: %v", mergeError.Line, mergeError.Err)
}

func (mergeError *MergeError) Unwrap() error {
	return mergeError.Err
}

func Sentinels() []error {
	return []error{
		ErrDigestMismatch,
		ErrSchemaInvalid,
		ErrRedactedWithoutOriginal,
		ErrSecretContextChanged,
		ErrNestingTooDeep,
		ErrMergedStructureChanged,
	}
}
