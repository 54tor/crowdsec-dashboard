package secondfactor

import (
	"errors"
	"sync"
	"testing"
)

func TestSetupRecoveryCodesRequireConfirmedFactor(testContext *testing.T) {
	setup := &Setup{}
	if _, beginError := setup.BeginTOTP("alice"); beginError != nil {
		testContext.Fatal(beginError)
	}

	if _, codesError := setup.RecoveryCodes(); !errors.Is(codesError, ErrNoConfirmedFactor) {
		testContext.Fatalf("expected ErrNoConfirmedFactor, got %v", codesError)
	}
	if setup.Ready() {
		testContext.Error("setup must not be ready before confirmation")
	}
}

func TestSetupBeginTOTPIsIdempotent(testContext *testing.T) {
	setup := &Setup{}

	firstEnrollment, firstError := setup.BeginTOTP("alice")
	secondEnrollment, secondError := setup.BeginTOTP("alice")

	if firstError != nil || secondError != nil || firstEnrollment != secondEnrollment {
		testContext.Fatalf("expected identical enrollments, got %v / %v", firstEnrollment, secondEnrollment)
	}
}

func TestSetupBeginTOTPConcurrentCallsReturnSameSecret(testContext *testing.T) {
	setup := &Setup{}
	const callCount = 10
	secrets := make([]string, callCount)
	var waitGroup sync.WaitGroup
	for callIndex := 0; callIndex < callCount; callIndex++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			enrollment, _ := setup.BeginTOTP("alice")
			secrets[callIndex] = enrollment.Secret
		}()
	}
	waitGroup.Wait()

	for _, observedSecret := range secrets {
		if observedSecret == "" || observedSecret != secrets[0] {
			testContext.Fatalf("secrets differ: %v", secrets)
		}
	}
}

func TestSetupConfirmTOTPRejectsWrongCode(testContext *testing.T) {
	setup := &Setup{}
	if _, beginError := setup.BeginTOTP("alice"); beginError != nil {
		testContext.Fatal(beginError)
	}

	if confirmError := setup.ConfirmTOTP("000000", referenceInstant); !errors.Is(confirmError, ErrInvalidCode) {
		testContext.Fatalf("expected ErrInvalidCode, got %v", confirmError)
	}
	if confirmError := (&Setup{}).ConfirmTOTP("000000", referenceInstant); !errors.Is(confirmError, ErrInvalidCode) {
		testContext.Fatalf("confirm without begin: expected ErrInvalidCode, got %v", confirmError)
	}
}

func TestSetupConfirmedFactorYieldsStableRecoveryCodesAndReady(testContext *testing.T) {
	setup := &Setup{}
	enrollment, _ := setup.BeginTOTP("alice")
	if confirmError := setup.ConfirmTOTP(codeAt(testContext, enrollment.Secret, referenceInstant), referenceInstant); confirmError != nil {
		testContext.Fatal(confirmError)
	}

	firstCodes, firstError := setup.RecoveryCodes()
	secondCodes, secondError := setup.RecoveryCodes()

	if firstError != nil || secondError != nil || len(firstCodes) != 10 || firstCodes[0] != secondCodes[0] {
		testContext.Fatalf("unstable codes: %v %v", firstCodes, secondCodes)
	}
	if !setup.Ready() {
		testContext.Error("expected ready")
	}
}
