package sidecarauth

const (
	CodeInvalidToken      = "invalid_token"
	CodeUnknownKey        = "unknown_key"
	CodeWrongIssuer       = "wrong_issuer"
	CodeWrongAudience     = "wrong_audience"
	CodeTokenExpired      = "token_expired"
	CodeLifetimeTooLong   = "token_lifetime_too_long"
	CodeClockSkew         = "clock_skew"
	CodeReplayed          = "token_replayed"
	CodeReplayCacheFull   = "replay_cache_full"
	CodeIssuedBeforeStart = "token_before_start"
	CodeRequestMismatch   = "request_mismatch"
	CodeBodyMismatch      = "body_mismatch"
)

type RefusalError struct {
	Code string
}

func (refusal *RefusalError) Error() string {
	return "sidecar token refused: " + refusal.Code
}

func refuse(code string) error {
	return &RefusalError{Code: code}
}
