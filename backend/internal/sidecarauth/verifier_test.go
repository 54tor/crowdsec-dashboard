package sidecarauth

import (
	"net/http"
	"testing"
	"time"
)

func TestVerifierAcceptsAFreshBoundToken(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(5*time.Second))
	token := mustSign(testContext, newTestSigner(fixture.key), testMethod, testRequestURI, testBody)

	binding, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

	expectAccepted(testContext, verifyError)
	if bodyError := binding.Check(testBody); bodyError != nil {
		testContext.Fatalf("expected the signed body to match, got %v", bodyError)
	}
}

func TestVerifierClaimsTheTokenUntilExpiryPlusSkew(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(5*time.Second))
	token := mustSign(testContext, newTestSigner(fixture.key), testMethod, testRequestURI, testBody)

	_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

	expectAccepted(testContext, verifyError)
	if len(fixture.claimer.claimedTokens) != 1 {
		testContext.Fatalf("expected exactly one claimed token, got %d", len(fixture.claimer.claimedTokens))
	}
	expectedClaimExpiry := signingTime.Add(TokenLifetime + MaxClockSkew)
	for claimedTokenID, claimedExpiry := range fixture.claimer.claimedTokens {
		if len(claimedTokenID) != 32 {
			testContext.Fatalf("expected a 128-bit hex jti, got %d characters", len(claimedTokenID))
		}
		if !claimedExpiry.Equal(expectedClaimExpiry) {
			testContext.Fatalf("expected claim kept until %v, got %v", expectedClaimExpiry, claimedExpiry)
		}
	}
}

func TestVerifierRefusesAReplayedToken(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(5*time.Second))
	token := mustSign(testContext, newTestSigner(fixture.key), testMethod, testRequestURI, testBody)

	_, firstError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)
	_, secondError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

	expectAccepted(testContext, firstError)
	expectRefusal(testContext, secondError, CodeReplayed)
}

func TestVerifierRefusesAnotherMethodPathOrQuery(testContext *testing.T) {
	mismatchedRequests := []struct {
		name       string
		method     string
		requestURI string
	}{
		{name: "other method", method: http.MethodGet, requestURI: "/v1/files?x=1"},
		{name: "other path", method: http.MethodPost, requestURI: "/v1/exec"},
		{name: "other query", method: http.MethodPost, requestURI: "/v1/files?x=2"},
		{name: "query dropped", method: http.MethodPost, requestURI: "/v1/files"},
	}
	for _, mismatchedRequest := range mismatchedRequests {
		testContext.Run(mismatchedRequest.name, func(subtestContext *testing.T) {
			fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
			token := mustSign(subtestContext, newTestSigner(fixture.key), http.MethodPost, "/v1/files?x=1", nil)

			_, verifyError := fixture.verifier.Verify("Bearer "+token, mismatchedRequest.method, mismatchedRequest.requestURI)

			expectRefusal(subtestContext, verifyError, CodeRequestMismatch)
			if len(fixture.claimer.claimedTokens) != 0 {
				subtestContext.Fatal("a mismatched request must not consume the token")
			}
		})
	}
}

func TestBodyBindingRefusesAnotherBody(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	signer := newTestSigner(fixture.key)
	tokenForBody := mustSign(testContext, signer, testMethod, testRequestURI, []byte(`{"a":1}`))
	tokenForEmptyBody := mustSign(testContext, signer, testMethod, testRequestURI, nil)

	bodyBinding, verifyError := fixture.verifier.Verify("Bearer "+tokenForBody, testMethod, testRequestURI)
	expectAccepted(testContext, verifyError)
	expectRefusal(testContext, bodyBinding.Check([]byte("{}")), CodeBodyMismatch)
	expectRefusal(testContext, bodyBinding.Check(nil), CodeBodyMismatch)

	emptyBodyBinding, emptyVerifyError := fixture.verifier.Verify("Bearer "+tokenForEmptyBody, testMethod, testRequestURI)
	expectAccepted(testContext, emptyVerifyError)
	if emptyBodyError := emptyBodyBinding.Check(nil); emptyBodyError != nil {
		testContext.Fatalf("expected the empty body to match, got %v", emptyBodyError)
	}
	expectRefusal(testContext, emptyBodyBinding.Check([]byte(" ")), CodeBodyMismatch)
}

func TestZeroBodyBindingRefusesEveryBody(testContext *testing.T) {
	var zeroBinding BodyBinding

	expectRefusal(testContext, zeroBinding.Check(nil), CodeBodyMismatch)
	expectRefusal(testContext, zeroBinding.Check(testBody), CodeBodyMismatch)
}

func TestVerifierRefusesWrongIssuerAudienceOrKey(testContext *testing.T) {
	testContext.Run("wrong issuer", func(subtestContext *testing.T) {
		fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
		foreignSigner := NewSigner("other.example.com", testAudience, fixture.key, fixedClock(signingTime))
		token := mustSign(subtestContext, foreignSigner, testMethod, testRequestURI, testBody)

		_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

		expectRefusal(subtestContext, verifyError, CodeWrongIssuer)
	})
	testContext.Run("wrong audience", func(subtestContext *testing.T) {
		fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
		foreignSigner := NewSigner(testIssuer, "engine-beta", fixture.key, fixedClock(signingTime))
		token := mustSign(subtestContext, foreignSigner, testMethod, testRequestURI, testBody)

		_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

		expectRefusal(subtestContext, verifyError, CodeWrongAudience)
	})
	testContext.Run("unknown key id", func(subtestContext *testing.T) {
		fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
		untrustedKey := mustGenerateSigningKey(subtestContext)
		token := mustSign(subtestContext, newTestSigner(untrustedKey), testMethod, testRequestURI, testBody)

		_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

		expectRefusal(subtestContext, verifyError, CodeUnknownKey)
	})
	testContext.Run("other key pair under the trusted key id", func(subtestContext *testing.T) {
		fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
		impostorKey := mustGenerateSigningKey(subtestContext)
		impostorKey.KeyID = fixture.key.KeyID
		token := mustSign(subtestContext, newTestSigner(impostorKey), testMethod, testRequestURI, testBody)

		_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

		expectRefusal(subtestContext, verifyError, CodeInvalidToken)
	})
}

func TestVerifierRefusesLifetimeAboveThirtySeconds(testContext *testing.T) {
	testContext.Run("expiry 31 s after issue", func(subtestContext *testing.T) {
		fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
		claims := boundClaims(signingTime)
		claims["exp"] = signingTime.Add(31 * time.Second).Format(time.RFC3339)
		token := signHandBuiltToken(subtestContext, fixture.key, footerFor(fixture.key.KeyID), claims)

		_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

		expectRefusal(subtestContext, verifyError, CodeLifetimeTooLong)
	})
	testContext.Run("expiry 31 s after not-before", func(subtestContext *testing.T) {
		fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
		claims := boundClaims(signingTime)
		claims["nbf"] = signingTime.Add(-time.Second).Format(time.RFC3339)
		token := signHandBuiltToken(subtestContext, fixture.key, footerFor(fixture.key.KeyID), claims)

		_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

		expectRefusal(subtestContext, verifyError, CodeLifetimeTooLong)
	})
	testContext.Run("expiry exactly 30 s after issue", func(subtestContext *testing.T) {
		fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
		claims := boundClaims(signingTime)
		claims["exp"] = signingTime.Add(30 * time.Second).Format(time.RFC3339)
		token := signHandBuiltToken(subtestContext, fixture.key, footerFor(fixture.key.KeyID), claims)

		_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

		expectAccepted(subtestContext, verifyError)
	})
}

func TestVerifierReportsClockSkewBeyondThirtySeconds(testContext *testing.T) {
	verifierNow := signingTime
	shiftedTokens := []struct {
		name         string
		issuedAt     time.Time
		expectedCode string
	}{
		{name: "issued 31 s in the future", issuedAt: verifierNow.Add(31 * time.Second), expectedCode: CodeClockSkew},
		{name: "issued 29 s in the future", issuedAt: verifierNow.Add(29 * time.Second)},
		{name: "issued 30 s in the future", issuedAt: verifierNow.Add(30 * time.Second)},
		{name: "expired 31 s ago", issuedAt: verifierNow.Add(-31*time.Second - TokenLifetime), expectedCode: CodeTokenExpired},
		{name: "expired 29 s ago", issuedAt: verifierNow.Add(-29*time.Second - TokenLifetime)},
		{name: "expired 30 s ago", issuedAt: verifierNow.Add(-30*time.Second - TokenLifetime)},
	}
	for _, shiftedToken := range shiftedTokens {
		testContext.Run(shiftedToken.name, func(subtestContext *testing.T) {
			fixture := newVerifierFixture(subtestContext, verifierNow)
			fixture.verifier.settings.StartedAt = shiftedToken.issuedAt.Add(-time.Hour)
			token := signHandBuiltToken(subtestContext, fixture.key, footerFor(fixture.key.KeyID), boundClaims(shiftedToken.issuedAt))

			_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

			if shiftedToken.expectedCode == "" {
				expectAccepted(subtestContext, verifyError)
				return
			}
			expectRefusal(subtestContext, verifyError, shiftedToken.expectedCode)
		})
	}
}

func TestVerifierReportsClockSkewOnAFutureNotBefore(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime)
	claims := boundClaims(signingTime)
	claims["nbf"] = signingTime.Add(31 * time.Second).Format(time.RFC3339)
	claims["exp"] = signingTime.Add(31 * time.Second).Format(time.RFC3339)
	claims["iat"] = signingTime.Add(time.Second).Format(time.RFC3339)
	token := signHandBuiltToken(testContext, fixture.key, footerFor(fixture.key.KeyID), claims)

	_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

	expectRefusal(testContext, verifyError, CodeClockSkew)
}

func TestVerifierRefusesTokenIssuedBeforeStart(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	token := mustSign(testContext, newTestSigner(fixture.key), testMethod, testRequestURI, testBody)
	fixture.verifier.settings.StartedAt = signingTime.Add(time.Nanosecond)

	_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

	expectRefusal(testContext, verifyError, CodeIssuedBeforeStart)
}

func TestVerifierAcceptsTokenIssuedAtStart(testContext *testing.T) {
	fixture := newVerifierFixture(testContext, signingTime.Add(time.Second))
	token := mustSign(testContext, newTestSigner(fixture.key), testMethod, testRequestURI, testBody)
	fixture.verifier.settings.StartedAt = signingTime

	_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

	expectAccepted(testContext, verifyError)
}

func TestVerifierRefusesMissingClaims(testContext *testing.T) {
	for _, missingClaim := range []string{"iss", "aud", "iat", "nbf", "exp", "jti", "htm", "htu", "bdh"} {
		testContext.Run(missingClaim, func(subtestContext *testing.T) {
			fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
			claims := boundClaims(signingTime)
			delete(claims, missingClaim)
			token := signHandBuiltToken(subtestContext, fixture.key, footerFor(fixture.key.KeyID), claims)

			_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

			expectRefusal(subtestContext, verifyError, CodeInvalidToken)
		})
	}
}

func TestVerifierRefusesClaimsOfTheWrongType(testContext *testing.T) {
	wronglyTypedClaims := map[string]any{
		"iat": 1767323045,
		"jti": 42,
		"htm": []string{testMethod},
		"bdh": "",
	}
	for claimName, wrongValue := range wronglyTypedClaims {
		testContext.Run(claimName, func(subtestContext *testing.T) {
			fixture := newVerifierFixture(subtestContext, signingTime.Add(time.Second))
			claims := boundClaims(signingTime)
			claims[claimName] = wrongValue
			token := signHandBuiltToken(subtestContext, fixture.key, footerFor(fixture.key.KeyID), claims)

			_, verifyError := fixture.verifier.Verify("Bearer "+token, testMethod, testRequestURI)

			expectRefusal(subtestContext, verifyError, CodeInvalidToken)
		})
	}
}

func TestVerifierRefusesWhenNotFullyConfigured(testContext *testing.T) {
	trustedKey := mustGenerateSigningKey(testContext)
	token := mustSign(testContext, newTestSigner(trustedKey), testMethod, testRequestURI, testBody)
	completeSettings := VerifierSettings{
		Issuer:    testIssuer,
		Audience:  testAudience,
		Keys:      staticKeys{trustedKey.KeyID: trustedKey.secret.Public()},
		Replay:    newMemoryClaimer(),
		StartedAt: signingTime.Add(-time.Minute),
		Now:       fixedClock(signingTime.Add(time.Second)),
	}
	incompleteSettings := map[string]func(settings *VerifierSettings){
		"no key lookup": func(settings *VerifierSettings) { settings.Keys = nil },
		"no replay":     func(settings *VerifierSettings) { settings.Replay = nil },
		"no clock":      func(settings *VerifierSettings) { settings.Now = nil },
		"no issuer":     func(settings *VerifierSettings) { settings.Issuer = "" },
		"no audience":   func(settings *VerifierSettings) { settings.Audience = "" },
		"no start time": func(settings *VerifierSettings) { settings.StartedAt = time.Time{} },
	}
	for caseName, removeSetting := range incompleteSettings {
		testContext.Run(caseName, func(subtestContext *testing.T) {
			settings := completeSettings
			settings.Replay = newMemoryClaimer()
			removeSetting(&settings)

			_, verifyError := NewVerifier(settings).Verify("Bearer "+token, testMethod, testRequestURI)

			expectRefusal(subtestContext, verifyError, CodeInvalidToken)
		})
	}
}
