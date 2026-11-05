package sidecarauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
)

const (
	testIssuer     = "dashboard.example.com"
	testAudience   = "engine-alpha"
	testMethod     = http.MethodPost
	testRequestURI = "/v1/exec"
)

var testBody = []byte(`{"command":"version"}`)

// Whole seconds on purpose: PASETO time claims are RFC 3339 without fractions,
// so boundary cases (exactly 30 s, 31 s) stay exact.
var signingTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

// staticKeys is the smallest KeyLookup: a fixed map from kid to public key.
type staticKeys map[string]paseto.V4AsymmetricPublicKey

func (keys staticKeys) Lookup(keyID string) (paseto.V4AsymmetricPublicKey, bool) {
	publicKey, found := keys[keyID]
	return publicKey, found
}

// memoryClaimer stands in for the replay cache of Task 2: it accepts each jti
// once and remembers the expiry the verifier asked it to keep.
type memoryClaimer struct {
	claimedTokens map[string]time.Time
}

func newMemoryClaimer() *memoryClaimer {
	return &memoryClaimer{claimedTokens: map[string]time.Time{}}
}

func (claimer *memoryClaimer) Claim(tokenID string, expiresAt time.Time) error {
	if _, alreadyClaimed := claimer.claimedTokens[tokenID]; alreadyClaimed {
		return &RefusalError{Code: CodeReplayed}
	}
	claimer.claimedTokens[tokenID] = expiresAt
	return nil
}

func fixedClock(moment time.Time) func() time.Time {
	return func() time.Time { return moment }
}

func mustGenerateSigningKey(testContext *testing.T) SigningKey {
	testContext.Helper()
	generatedKey, generateError := GenerateSigningKey()
	if generateError != nil {
		testContext.Fatalf("GenerateSigningKey: %v", generateError)
	}
	return generatedKey
}

type verifierFixture struct {
	key      SigningKey
	claimer  *memoryClaimer
	verifier *Verifier
}

// newVerifierFixture trusts one fresh key, starts the sidecar one minute before
// signingTime and pins the verifier clock to verifierNow.
func newVerifierFixture(testContext *testing.T, verifierNow time.Time) verifierFixture {
	testContext.Helper()
	trustedKey := mustGenerateSigningKey(testContext)
	claimer := newMemoryClaimer()
	verifier := NewVerifier(VerifierSettings{
		Issuer:    testIssuer,
		Audience:  testAudience,
		Keys:      staticKeys{trustedKey.KeyID: trustedKey.secret.Public()},
		Replay:    claimer,
		StartedAt: signingTime.Add(-time.Minute),
		Now:       fixedClock(verifierNow),
	})
	return verifierFixture{key: trustedKey, claimer: claimer, verifier: verifier}
}

func newTestSigner(key SigningKey) Signer {
	return NewSigner(testIssuer, testAudience, key, fixedClock(signingTime))
}

func mustSign(testContext *testing.T, signer Signer, method, requestURI string, body []byte) string {
	testContext.Helper()
	token, signError := signer.Sign(method, requestURI, body)
	if signError != nil {
		testContext.Fatalf("Sign: %v", signError)
	}
	return token
}

// expectRefusal checks the code and the whole message, so a refusal that would
// echo the token or any other detail fails the test.
func expectRefusal(testContext *testing.T, verifyError error, expectedCode string) {
	testContext.Helper()
	var refusal *RefusalError
	if !errors.As(verifyError, &refusal) {
		testContext.Fatalf("expected refusal %q, got %v", expectedCode, verifyError)
	}
	if refusal.Code != expectedCode {
		testContext.Fatalf("expected refusal %q, got %q", expectedCode, refusal.Code)
	}
	expectedMessage := "sidecar token refused: " + expectedCode
	if verifyError.Error() != expectedMessage {
		testContext.Fatalf("expected message %q, got %q", expectedMessage, verifyError.Error())
	}
}

func expectAccepted(testContext *testing.T, verifyError error) {
	testContext.Helper()
	if verifyError != nil {
		testContext.Fatalf("expected the token to be accepted, got %v", verifyError)
	}
}

func hexSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// boundClaims returns every claim the signer writes, valid for testMethod,
// testRequestURI and testBody, so a case only overrides the claim it attacks.
func boundClaims(issuedAt time.Time) map[string]any {
	return map[string]any{
		"iss": testIssuer,
		"aud": testAudience,
		"iat": issuedAt.Format(time.RFC3339),
		"nbf": issuedAt.Format(time.RFC3339),
		"exp": issuedAt.Add(TokenLifetime).Format(time.RFC3339),
		"jti": "0123456789abcdef0123456789abcdef",
		"htm": testMethod,
		"htu": testRequestURI,
		"bdh": hexSHA256(testBody),
	}
}

func footerFor(keyID string) string {
	return `{"kid":"` + keyID + `"}`
}

// signHandBuiltToken signs arbitrary claims with the real secret key. The
// Signer always writes a 30 s lifetime from its clock and every claim, so
// tokens with a longer lifetime, shifted times, missing claims or an odd
// footer can only be produced this way.
func signHandBuiltToken(testContext *testing.T, key SigningKey, footer string, claims map[string]any) string {
	testContext.Helper()
	token := paseto.NewToken()
	for claimName, claimValue := range claims {
		if setError := token.Set(claimName, claimValue); setError != nil {
			testContext.Fatalf("set claim %s: %v", claimName, setError)
		}
	}
	token.SetFooter([]byte(footer))
	return token.V4Sign(key.secret, nil)
}
