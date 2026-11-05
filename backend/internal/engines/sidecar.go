package engines

import (
	"encoding/hex"
	"errors"

	"crowdsec-dashboard/internal/sidecarclient"
)

var (
	ErrEngineHasNoSidecar = errors.New("engine has no sidecar")
	ErrSidecarURLChange   = errors.New("sidecar url cannot change while a sidecar is configured")
	ErrNoNextSidecarKey   = errors.New("engine has no staged sidecar key")
)

type Sidecar struct {
	URL              string
	SPKISHA256       string
	KeyID            string
	PublicKeyHex     string
	NextKeyID        string
	NextPublicKeyHex string
}

type SidecarInput struct {
	URL        string
	SPKISHA256 string
}

func (row engineRow) sidecar() *Sidecar {
	if row.SidecarURL == nil || row.SidecarSPKISHA256 == nil || row.SidecarKeyID == nil || row.SidecarPublicKey == nil {
		return nil
	}
	configuredSidecar := &Sidecar{
		URL: *row.SidecarURL, SPKISHA256: *row.SidecarSPKISHA256,
		KeyID: *row.SidecarKeyID, PublicKeyHex: *row.SidecarPublicKey,
	}
	if row.SidecarNextKeyID != nil && row.SidecarNextPublicKey != nil {
		configuredSidecar.NextKeyID, configuredSidecar.NextPublicKeyHex = *row.SidecarNextKeyID, *row.SidecarNextPublicKey
	}
	return configuredSidecar
}

func normalizedSidecarInput(input SidecarInput) (SidecarInput, error) {
	if urlError := ValidateSidecarURL(input.URL); urlError != nil {
		return SidecarInput{}, invalidField("sidecar_url", urlError.Error())
	}
	pinDigest, pinError := sidecarclient.ParsePin(input.SPKISHA256)
	if pinError != nil {
		return SidecarInput{}, invalidField("sidecar_spki_sha256", "must be 64 hexadecimal characters")
	}
	return SidecarInput{URL: input.URL, SPKISHA256: hex.EncodeToString(pinDigest)}, nil
}
