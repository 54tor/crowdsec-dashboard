package sidecarauth

import (
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
)

// The verifier tests only prove that what the signer writes is accepted; this
// test pins the wire claims themselves, read back with the library alone.
func TestSignerWritesEveryBindingClaim(testContext *testing.T) {
	signingKey := mustGenerateSigningKey(testContext)
	signer := newTestSigner(signingKey)
	token := mustSign(testContext, signer, testMethod, "/v1/files?x=1", testBody)

	parsedToken, parseError := paseto.NewParserWithoutExpiryCheck().ParseV4Public(signingKey.secret.Public(), token, nil)
	if parseError != nil {
		testContext.Fatalf("library parse: %v", parseError)
	}

	expectedStringClaims := map[string]string{
		"iss": testIssuer,
		"aud": testAudience,
		"htm": testMethod,
		"htu": "/v1/files?x=1",
		"bdh": hexSHA256(testBody),
	}
	for claimName, expectedValue := range expectedStringClaims {
		obtainedValue, claimError := parsedToken.GetString(claimName)
		if claimError != nil || obtainedValue != expectedValue {
			testContext.Fatalf("claim %s: expected %q, got %q (%v)", claimName, expectedValue, obtainedValue, claimError)
		}
	}
	for _, timeClaim := range []string{"iat", "nbf"} {
		obtainedTime, timeError := parsedToken.GetTime(timeClaim)
		if timeError != nil || !obtainedTime.Equal(signingTime) {
			testContext.Fatalf("claim %s: expected %v, got %v (%v)", timeClaim, signingTime, obtainedTime, timeError)
		}
	}
	expiration, expirationError := parsedToken.GetExpiration()
	if expirationError != nil || !expiration.Equal(signingTime.Add(TokenLifetime)) {
		testContext.Fatalf("exp: expected %v, got %v (%v)", signingTime.Add(TokenLifetime), expiration, expirationError)
	}
	if string(parsedToken.Footer()) != footerFor(signingKey.KeyID) {
		testContext.Fatalf("footer: expected %s, got %s", footerFor(signingKey.KeyID), parsedToken.Footer())
	}
	if signer.KeyID() != signingKey.KeyID {
		testContext.Fatalf("KeyID: expected %q, got %q", signingKey.KeyID, signer.KeyID())
	}
}

func TestSignerUsesAFreshTokenIDEachTime(testContext *testing.T) {
	signingKey := mustGenerateSigningKey(testContext)
	signer := newTestSigner(signingKey)
	parser := paseto.NewParserWithoutExpiryCheck()
	seenTokenIDs := map[string]bool{}

	for signatureNumber := 0; signatureNumber < 3; signatureNumber++ {
		token := mustSign(testContext, signer, testMethod, testRequestURI, testBody)
		parsedToken, parseError := parser.ParseV4Public(signingKey.secret.Public(), token, nil)
		if parseError != nil {
			testContext.Fatalf("library parse: %v", parseError)
		}
		tokenID, tokenIDError := parsedToken.GetJti()
		if tokenIDError != nil || len(tokenID) != 32 || seenTokenIDs[tokenID] {
			testContext.Fatalf("expected a new 128-bit hex jti, got %q (%v)", tokenID, tokenIDError)
		}
		seenTokenIDs[tokenID] = true
	}
}

func TestSignerRefusesToProduceATokenAboveTheMaximumLength(testContext *testing.T) {
	signer := newTestSigner(mustGenerateSigningKey(testContext))
	oversizedRequestURI := "/" + strings.Repeat("a", maxTokenLength)

	token, signError := signer.Sign(testMethod, oversizedRequestURI, testBody)

	if signError == nil {
		testContext.Fatalf("expected an error, got a token of %d characters", len(token))
	}
	if token != "" {
		testContext.Fatal("no token may be returned alongside the error")
	}
}

func TestSignerWritesTimeClaimsWithSubSecondPrecision(testContext *testing.T) {
	signingKey := mustGenerateSigningKey(testContext)
	signingTimeWithNanoseconds := signingTime.Add(123456789 * time.Nanosecond)
	signer := NewSigner(testIssuer, testAudience, signingKey, fixedClock(signingTimeWithNanoseconds))
	token := mustSign(testContext, signer, testMethod, testRequestURI, testBody)

	parsedToken, parseError := paseto.NewParserWithoutExpiryCheck().ParseV4Public(signingKey.secret.Public(), token, nil)
	if parseError != nil {
		testContext.Fatalf("library parse: %v", parseError)
	}

	issuedAt, issuedAtError := parsedToken.GetIssuedAt()
	if issuedAtError != nil || !issuedAt.Equal(signingTimeWithNanoseconds) {
		testContext.Fatalf("iat: expected %v, got %v (%v)", signingTimeWithNanoseconds, issuedAt, issuedAtError)
	}
}
