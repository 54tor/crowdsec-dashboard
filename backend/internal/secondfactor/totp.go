package secondfactor

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	totpIssuer        = "CrowdSec Dashboard"
	totpPeriodSeconds = 30
)

var ErrInvalidCode = errors.New("invalid code")

var totpValidationOptions = totp.ValidateOpts{
	Period:    totpPeriodSeconds,
	Digits:    otp.DigitsSix,
	Algorithm: otp.AlgorithmSHA1,
}

func NewTOTPKey(accountName string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: accountName,
		Period:      totpPeriodSeconds,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
}

func MatchTOTP(secret, code string, now time.Time) (int64, bool) {
	var matchedStep int64
	isMatched := false
	for _, stepOffset := range []time.Duration{-totpPeriodSeconds * time.Second, 0, totpPeriodSeconds * time.Second} {
		candidateInstant := now.Add(stepOffset)
		expectedCode, generateError := totp.GenerateCodeCustom(secret, candidateInstant, totpValidationOptions)
		if generateError != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(expectedCode), []byte(code)) == 1 {
			matchedStep = candidateInstant.Unix() / totpPeriodSeconds
			isMatched = true
		}
	}
	return matchedStep, isMatched
}
