package auth

import (
	"testing"

	"github.com/alexedwards/argon2id"
)

var fastTestParams = &argon2id.Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func hashForTest(testContext *testing.T, password string) string {
	testContext.Helper()
	encodedHash, hashError := argon2id.CreateHash(password, fastTestParams)
	if hashError != nil {
		testContext.Fatal(hashError)
	}
	return encodedHash
}

func TestVerifyPasswordAcceptsCorrectPassword(testContext *testing.T) {
	encodedHash := hashForTest(testContext, "correct horse")

	if !VerifyPassword(encodedHash, "correct horse") {
		testContext.Error("expected correct password to verify")
	}
}

func TestVerifyPasswordRejectsWrongPassword(testContext *testing.T) {
	encodedHash := hashForTest(testContext, "correct horse")

	if VerifyPassword(encodedHash, "wrong horse") {
		testContext.Error("expected wrong password to be rejected")
	}
}

func TestVerifyPasswordRejectsMalformedHash(testContext *testing.T) {
	if VerifyPassword("not-a-hash", "anything") {
		testContext.Error("expected malformed hash to be rejected")
	}
}
