package cscli

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func DecodeList[T any](raw []byte) ([]T, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []T{}, nil
	}
	var decoded []T
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return nil, fmt.Errorf("decode cscli list: %w", err)
	}
	if decoded == nil {
		return []T{}, nil
	}
	return decoded, nil
}
