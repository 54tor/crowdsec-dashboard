package sidecarclient

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func ParsePin(pin string) ([]byte, error) {
	digest, decodeError := hex.DecodeString(pin)
	if decodeError != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w: expected %d hexadecimal characters", ErrInvalidPin, 2*sha256.Size)
	}
	return digest, nil
}
