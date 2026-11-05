package sidecarauth

import (
	"time"

	"aidanwoods.dev/go-paseto"
)

func readClaims(token *paseto.Token) (verifiedClaims, error) {
	var claims verifiedClaims
	stringClaims := map[string]*string{
		"iss":           &claims.issuer,
		"aud":           &claims.audience,
		"jti":           &claims.tokenID,
		claimMethod:     &claims.method,
		claimRequestURI: &claims.requestURI,
		claimBodyHash:   &claims.bodyHash,
	}
	for claimName, destination := range stringClaims {
		claimValue, claimError := token.GetString(claimName)
		if claimError != nil || claimValue == "" {
			return verifiedClaims{}, refuse(CodeInvalidToken)
		}
		*destination = claimValue
	}
	timeClaims := map[string]*time.Time{
		"iat": &claims.issuedAt,
		"nbf": &claims.notBefore,
		"exp": &claims.expiresAt,
	}
	for claimName, destination := range timeClaims {
		claimTime, claimError := token.GetTime(claimName)
		if claimError != nil {
			return verifiedClaims{}, refuse(CodeInvalidToken)
		}
		*destination = claimTime
	}
	return claims, nil
}
