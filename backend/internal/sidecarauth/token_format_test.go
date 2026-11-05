package sidecarauth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
)

// splitToken returns the four dot-separated parts of a footer-carrying token:
// "v4", "public", payload, footer.
func splitToken(testContext *testing.T, token string) []string {
	testContext.Helper()
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 4 {
		testContext.Fatalf("expected a token with a footer, got %d parts", len(tokenParts))
	}
	return tokenParts
}

// nonCanonicalVariant flips one of the unused low bits of the last base64
// character. A lenient decoder returns the same bytes, so a verifier that is
// not strict would accept a second spelling of the same signed token.
func nonCanonicalVariant(testContext *testing.T, canonicalSegment string) string {
	testContext.Helper()
	const urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(canonicalSegment)%4 == 0 {
		testContext.Fatal("segment has no unused bits; pick a length that is not a multiple of 3 bytes")
	}
	lastCharacterIndex := strings.IndexByte(urlAlphabet, canonicalSegment[len(canonicalSegment)-1])
	variantSegment := canonicalSegment[:len(canonicalSegment)-1] + string(urlAlphabet[lastCharacterIndex^1])

	canonicalBytes, canonicalError := base64.RawURLEncoding.DecodeString(canonicalSegment)
	variantBytes, variantError := base64.RawURLEncoding.DecodeString(variantSegment)
	if canonicalError != nil || variantError != nil || string(canonicalBytes) != string(variantBytes) {
		testContext.Fatal("variant must decode leniently to the same bytes, otherwise the test proves nothing")
	}
	return variantSegment
}

func TestVerifierRefusesATamperedPayload(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	token := mustSign(testContext, newTestSigner(fixture.key), testMethod, testRequestURI, testBody)
	tokenParts := splitToken(testContext, token)
	payloadBytes, decodeError := base64.RawURLEncoding.DecodeString(tokenParts[2])
	if decodeError != nil {
		testContext.Fatalf("decode payload: %v", decodeError)
	}
	payloadBytes[len(payloadBytes)/4] ^= 0x01
	tokenParts[2] = base64.RawURLEncoding.EncodeToString(payloadBytes)

	_, verifyError := fixture.verifier.Verify("Bearer "+strings.Join(tokenParts, "."), testMethod, testRequestURI)

	expectRefusal(testContext, verifyError, CodeInvalidToken)
}

func TestVerifierRefusesATamperedFooter(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	token := mustSign(testContext, newTestSigner(fixture.key), testMethod, testRequestURI, testBody)
	tokenParts := splitToken(testContext, token)
	tamperedFooter := `{"kid":"` + fixture.key.KeyID + `","extra":true}`
	tokenParts[3] = base64.RawURLEncoding.EncodeToString([]byte(tamperedFooter))

	_, verifyError := fixture.verifier.Verify("Bearer "+strings.Join(tokenParts, "."), testMethod, testRequestURI)

	expectRefusal(testContext, verifyError, CodeInvalidToken)
}

func TestVerifierRefusesUnreadableFooters(testContext *testing.T) {
	unreadableFooters := map[string]string{
		"not json":     "kid",
		"empty kid":    `{"kid":""}`,
		"kid a number": `{"kid":7}`,
		"no kid":       `{"key":"x"}`,
	}
	for caseName, unreadableFooter := range unreadableFooters {
		testContext.Run(caseName, func(subtestContext *testing.T) {
			fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
			token := signHandBuiltToken(subtestContext, fixture.key, unreadableFooter, boundClaims(signingTime))

			_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

			expectRefusal(subtestContext, verifyError, CodeInvalidToken)
		})
	}
}

func TestVerifierRefusesATokenWithoutFooter(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	token := signHandBuiltToken(testContext, fixture.key, "", boundClaims(signingTime))

	_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

	expectRefusal(testContext, verifyError, CodeInvalidToken)
}

func TestVerifierRefusesOtherPasetoVersionsAndPurposes(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	claimedToken := paseto.NewToken()
	for claimName, claimValue := range boundClaims(signingTime) {
		if setError := claimedToken.Set(claimName, claimValue); setError != nil {
			testContext.Fatalf("set claim %s: %v", claimName, setError)
		}
	}
	claimedToken.SetFooter([]byte(footerFor(fixture.key.KeyID)))
	foreignTokens := map[string]string{
		"v4.local":  claimedToken.V4Encrypt(paseto.NewV4SymmetricKey(), nil),
		"v3.public": claimedToken.V3Sign(paseto.NewV3AsymmetricSecretKey(), nil),
		"v2.public": claimedToken.V2Sign(paseto.NewV2AsymmetricSecretKey()),
	}
	for caseName, foreignToken := range foreignTokens {
		testContext.Run(caseName, func(subtestContext *testing.T) {
			_, verifyError := fixture.verifier.Verify("Bearer "+foreignToken, testMethod, testRequestURI)

			expectRefusal(subtestContext, verifyError, CodeInvalidToken)
		})
	}
}

func TestVerifierRefusesNonCanonicalEncodings(testContext *testing.T) {
	// A 43-byte footer (one space added to the 42-byte canonical form) leaves
	// four unused bits in its last base64 character.
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	paddedFooter := `{"kid":"` + fixture.key.KeyID + `" }`
	canonicalToken := signHandBuiltToken(testContext, fixture.key, paddedFooter, boundClaims(signingTime))
	tokenParts := splitToken(testContext, canonicalToken)
	tokenParts[3] = nonCanonicalVariant(testContext, tokenParts[3])
	variantToken := strings.Join(tokenParts, ".")

	_, variantError := fixture.verifier.Verify("Bearer "+variantToken, testMethod, testRequestURI)
	_, canonicalError := fixture.verifier.Verify("Bearer "+canonicalToken, testMethod, testRequestURI)

	expectRefusal(testContext, variantError, CodeInvalidToken)
	expectAccepted(testContext, canonicalError)
}

func TestVerifierRefusesMalformedAuthorizationHeaders(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	token := mustSign(testContext, newTestSigner(fixture.key), testMethod, testRequestURI, testBody)
	malformedHeaders := map[string]string{
		"empty header":         "",
		"prefix only":          "Bearer ",
		"no prefix":            token,
		"lowercase prefix":     "bearer " + token,
		"double space":         "Bearer  " + token,
		"trailing space":       "Bearer " + token + " ",
		"embedded newline":     "Bearer " + token[:20] + "\n" + token[20:],
		"three parts only":     "Bearer " + strings.Join(splitToken(testContext, token)[:3], "."),
		"five parts":           "Bearer " + token + ".x",
		"garbage":              "Bearer not-a-token",
		"prefix in other case": "BEARER " + token,
	}
	for caseName, malformedHeader := range malformedHeaders {
		testContext.Run(caseName, func(subtestContext *testing.T) {
			_, verifyError := fixture.verifier.Verify(malformedHeader, testMethod, testRequestURI)

			expectRefusal(subtestContext, verifyError, CodeInvalidToken)
		})
	}
	if len(fixture.claimer.claimedTokens) != 0 {
		testContext.Fatal("a refused header must not consume the token")
	}
}

func TestVerifierRefusesAnOversizeToken(testContext *testing.T) {
	// The oversize token is otherwise valid (signed, bound to the URI it is
	// verified against), so only the size cap can refuse it.
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	longRequestURI := "/v1/files?path=" + strings.Repeat("a", maxTokenLength)
	claims := boundClaims(signingTime)
	claims["htu"] = longRequestURI
	oversizeToken := signHandBuiltToken(testContext, fixture.key, footerFor(fixture.key.KeyID), claims)
	if len(oversizeToken) <= maxTokenLength {
		testContext.Fatalf("token of %d bytes is not oversize", len(oversizeToken))
	}

	_, verifyError := fixture.verifier.Verify("Bearer "+oversizeToken, testMethod, longRequestURI)

	expectRefusal(testContext, verifyError, CodeInvalidToken)
}
