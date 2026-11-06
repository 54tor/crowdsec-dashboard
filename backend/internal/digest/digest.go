package digest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const redactedDigester = "Digester([REDACTED])"

type Digester struct {
	key []byte
}

func NewDigester(key []byte) Digester {
	return Digester{key: bytes.Clone(key)}
}

func (digester Digester) Of(rawContent []byte) string {
	mac := hmac.New(sha256.New, digester.key)
	mac.Write(rawContent)
	return hex.EncodeToString(mac.Sum(nil))
}

func (digester Digester) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedDigester))
}
