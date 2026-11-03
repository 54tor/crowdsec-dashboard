package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type bundleHeader struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
}

func Decode(reader io.Reader, maxBytes int64) (Bundle, error) {
	content, readError := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if readError != nil {
		return Bundle{}, ErrInvalid
	}
	if int64(len(content)) > maxBytes {
		return Bundle{}, ErrTooLarge
	}
	if !isWithinDepth(content, MaxDepth) {
		return Bundle{}, ErrInvalid
	}
	var header bundleHeader
	if headerError := json.Unmarshal(content, &header); headerError != nil || header.Format != Format {
		return Bundle{}, ErrInvalid
	}
	if header.Version != Version {
		return Bundle{}, ErrVersion
	}
	return decodeStrict(content)
}

func decodeStrict(content []byte) (Bundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var decoded Bundle
	if decodeError := decoder.Decode(&decoded); decodeError != nil {
		return Bundle{}, ErrInvalid
	}
	if _, trailingError := decoder.Token(); !errors.Is(trailingError, io.EOF) {
		return Bundle{}, ErrInvalid
	}
	return decoded, nil
}

func isWithinDepth(content []byte, maxDepth int) bool {
	decoder := json.NewDecoder(bytes.NewReader(content))
	depth := 0
	for {
		token, tokenError := decoder.Token()
		if errors.Is(tokenError, io.EOF) {
			return depth == 0
		}
		if tokenError != nil {
			return false
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			continue
		}
		if delimiter == '{' || delimiter == '[' {
			depth++
		} else {
			depth--
		}
		if depth > maxDepth {
			return false
		}
	}
}
