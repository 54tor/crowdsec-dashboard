package secondfactor

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

var referenceInstant = time.Unix(1_800_000_000, 0)

func newSecret(testContext *testing.T) string {
	testContext.Helper()
	key, keyError := NewTOTPKey("alice")
	if keyError != nil {
		testContext.Fatal(keyError)
	}
	return key.Secret()
}

func codeAt(testContext *testing.T, secret string, instant time.Time) string {
	testContext.Helper()
	code, codeError := totp.GenerateCodeCustom(secret, instant, totp.ValidateOpts{Period: 30, Digits: 6})
	if codeError != nil {
		testContext.Fatal(codeError)
	}
	return code
}

func TestMatchTOTPAcceptsPreviousCurrentAndNextStep(testContext *testing.T) {
	secret := newSecret(testContext)
	currentStep := referenceInstant.Unix() / 30

	for stepOffset := int64(-1); stepOffset <= 1; stepOffset++ {
		submittedCode := codeAt(testContext, secret, referenceInstant.Add(time.Duration(stepOffset)*30*time.Second))

		matchedStep, isMatched := MatchTOTP(secret, submittedCode, referenceInstant)

		if !isMatched || matchedStep != currentStep+stepOffset {
			testContext.Errorf("offset %d: expected step %d, got %d matched=%v", stepOffset, currentStep+stepOffset, matchedStep, isMatched)
		}
	}
}

func TestMatchTOTPRejectsTwoStepsAway(testContext *testing.T) {
	secret := newSecret(testContext)

	for _, stepOffset := range []time.Duration{-60 * time.Second, 60 * time.Second} {
		if _, isMatched := MatchTOTP(secret, codeAt(testContext, secret, referenceInstant.Add(stepOffset)), referenceInstant); isMatched {
			testContext.Errorf("offset %v must not match", stepOffset)
		}
	}
}

func TestNewTOTPKeyUsesIssuerAndStandardParameters(testContext *testing.T) {
	key, keyError := NewTOTPKey("alice")
	if keyError != nil {
		testContext.Fatal(keyError)
	}
	if key.Issuer() != "CrowdSec Dashboard" || key.AccountName() != "alice" {
		testContext.Errorf("unexpected issuer/account: %q %q", key.Issuer(), key.AccountName())
	}
}
