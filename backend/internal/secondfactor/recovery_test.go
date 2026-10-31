package secondfactor

import (
	"bytes"
	"regexp"
	"testing"
)

var recoveryCodeFormat = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`)

func TestGenerateRecoveryCodesReturnsTenDistinctFormattedCodes(testContext *testing.T) {
	recoveryCodes, generateError := GenerateRecoveryCodes()
	if generateError != nil {
		testContext.Fatal(generateError)
	}
	if len(recoveryCodes) != 10 {
		testContext.Fatalf("expected 10 codes, got %d", len(recoveryCodes))
	}
	distinctCodes := map[string]bool{}
	for _, recoveryCode := range recoveryCodes {
		if !recoveryCodeFormat.MatchString(recoveryCode) {
			testContext.Errorf("bad format: %q", recoveryCode)
		}
		distinctCodes[recoveryCode] = true
	}
	if len(distinctCodes) != 10 {
		testContext.Errorf("codes are not distinct: %d", len(distinctCodes))
	}
}

func TestNormalizeRecoveryCodeIgnoresCaseDashesAndSpaces(testContext *testing.T) {
	normalizedCode := NormalizeRecoveryCode(" abcd-ef12 3456-789a ")

	if normalizedCode != "ABCDEF123456789A" {
		testContext.Errorf("got %q", normalizedCode)
	}
}

func TestNormalizeRecoveryCodeMapsCrockfordAliases(testContext *testing.T) {
	originalCode := "0123-1111-0000-ABCD"

	for _, aliasedCode := range []string{"o123-iiii-oooo-abcd", "O123-llll-OOOO-ABCD", "0123-LLLL-0000-abcd"} {
		if !bytes.Equal(HashRecoveryCode(aliasedCode), HashRecoveryCode(originalCode)) {
			testContext.Errorf("%q must hash like the original", aliasedCode)
		}
	}
}
