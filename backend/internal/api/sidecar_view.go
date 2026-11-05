package api

import (
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/sidecarauth"
)

type sidecarView struct {
	URL           string `json:"url"`
	SPKISHA256    string `json:"spki_sha256"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
	NextKeyID     string `json:"next_key_id"`
	NextPublicKey string `json:"next_public_key"`
}

type sidecarObservationResponse struct {
	SPKISHA256 string `json:"spki_sha256"`
}

type sidecarEnrolmentResponse struct {
	Sidecar        *sidecarView `json:"sidecar"`
	TrustedKeyLine string       `json:"trusted_key_line"`
	Issuer         string       `json:"issuer"`
	Audience       string       `json:"audience"`
	Warning        string       `json:"warning,omitempty"`
}

type sidecarKeyResponse struct {
	Sidecar        *sidecarView `json:"sidecar"`
	TrustedKeyLine string       `json:"trusted_key_line"`
	Warning        string       `json:"warning,omitempty"`
}

func newSidecarView(configuredSidecar *engines.Sidecar) *sidecarView {
	if configuredSidecar == nil {
		return nil
	}
	return &sidecarView{
		URL:           configuredSidecar.URL,
		SPKISHA256:    configuredSidecar.SPKISHA256,
		KeyID:         configuredSidecar.KeyID,
		PublicKey:     configuredSidecar.PublicKeyHex,
		NextKeyID:     configuredSidecar.NextKeyID,
		NextPublicKey: configuredSidecar.NextPublicKeyHex,
	}
}

func currentTrustedKeyLine(configuredSidecar *engines.Sidecar) string {
	if configuredSidecar == nil {
		return ""
	}
	return sidecarauth.TrustedKeyLineOf(configuredSidecar.KeyID, configuredSidecar.PublicKeyHex)
}

func nextTrustedKeyLine(configuredSidecar *engines.Sidecar) string {
	if configuredSidecar == nil || configuredSidecar.NextKeyID == "" {
		return ""
	}
	return sidecarauth.TrustedKeyLineOf(configuredSidecar.NextKeyID, configuredSidecar.NextPublicKeyHex)
}
