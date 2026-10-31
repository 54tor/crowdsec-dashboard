package secondfactor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

const (
	recoveryCodeCount     = 10
	recoveryCodeBytes     = 10
	recoveryCodeGroupSize = 4
	crockfordAlphabet     = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var (
	crockfordEncoding    = base32.NewEncoding(crockfordAlphabet).WithPadding(base32.NoPadding)
	recoveryCodeReplacer = strings.NewReplacer("-", "", " ", "", "\t", "", "O", "0", "I", "1", "L", "1")
)

func GenerateRecoveryCodes() ([]string, error) {
	recoveryCodes := make([]string, 0, recoveryCodeCount)
	for len(recoveryCodes) < recoveryCodeCount {
		randomBytes := make([]byte, recoveryCodeBytes)
		if _, readError := rand.Read(randomBytes); readError != nil {
			return nil, fmt.Errorf("generate recovery code: %w", readError)
		}
		recoveryCodes = append(recoveryCodes, groupRecoveryCode(crockfordEncoding.EncodeToString(randomBytes)))
	}
	return recoveryCodes, nil
}

func groupRecoveryCode(encodedCode string) string {
	groups := make([]string, 0, len(encodedCode)/recoveryCodeGroupSize)
	for groupStart := 0; groupStart < len(encodedCode); groupStart += recoveryCodeGroupSize {
		groups = append(groups, encodedCode[groupStart:groupStart+recoveryCodeGroupSize])
	}
	return strings.Join(groups, "-")
}

func NormalizeRecoveryCode(input string) string {
	return recoveryCodeReplacer.Replace(strings.ToUpper(input))
}

func HashRecoveryCode(code string) []byte {
	codeDigest := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return codeDigest[:]
}
