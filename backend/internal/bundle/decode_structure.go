package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type structureFrame struct {
	isArray      bool
	elementCount int
	expectsKey   bool
}

type structureWalk struct {
	frames     []structureFrame
	valueCount int
}

func checkStructure(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	walk := structureWalk{}
	for {
		token, tokenError := decoder.Token()
		if errors.Is(tokenError, io.EOF) {
			return walk.finish()
		}
		if tokenError != nil {
			return ErrInvalid
		}
		if stepError := walk.step(token); stepError != nil {
			return stepError
		}
	}
}

func (walk *structureWalk) finish() error {
	if len(walk.frames) != 0 {
		return ErrInvalid
	}
	return nil
}

func (walk *structureWalk) step(token json.Token) error {
	delimiter, isDelimiter := token.(json.Delim)
	if isDelimiter && (delimiter == '}' || delimiter == ']') {
		walk.frames = walk.frames[:len(walk.frames)-1]
		return nil
	}
	if walk.consumesKey() {
		return nil
	}
	if countError := walk.countValue(); countError != nil {
		return countError
	}
	if !isDelimiter {
		return nil
	}
	walk.frames = append(walk.frames, structureFrame{isArray: delimiter == '[', expectsKey: delimiter == '{'})
	if len(walk.frames) > MaxDepth {
		return ErrInvalid
	}
	return nil
}

func (walk *structureWalk) consumesKey() bool {
	if len(walk.frames) == 0 {
		return false
	}
	parent := &walk.frames[len(walk.frames)-1]
	if parent.isArray || !parent.expectsKey {
		return false
	}
	parent.expectsKey = false
	return true
}

func (walk *structureWalk) countValue() error {
	walk.valueCount++
	if walk.valueCount > MaxValueCount {
		return ErrTooLarge
	}
	if len(walk.frames) == 0 {
		return nil
	}
	parent := &walk.frames[len(walk.frames)-1]
	if !parent.isArray {
		parent.expectsKey = true
		return nil
	}
	parent.elementCount++
	if parent.elementCount > MaxArrayLength {
		return ErrTooLarge
	}
	return nil
}
