package confwrite

import (
	"bytes"
	"errors"
)

var ErrChangedConcurrently = errors.New("confwrite: file changed since the caller read it")

type ExpectedState struct {
	Exists  bool
	Content []byte
}

func (expectation *ExpectedState) matches(current Current) bool {
	if expectation == nil {
		return true
	}
	if !expectation.Exists {
		return !current.Exists
	}
	return current.Exists && !current.Oversized && bytes.Equal(current.Content, expectation.Content)
}
