package auth

import "github.com/alexedwards/argon2id"

func VerifyPassword(encodedHash, candidate string) bool {
	matches, compareError := argon2id.ComparePasswordAndHash(candidate, encodedHash)
	return compareError == nil && matches
}
