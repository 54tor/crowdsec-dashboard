package engines

import (
	"fmt"

	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/sidecarauth"
)

type sealedSidecarKey struct {
	keyID        string
	publicKeyHex string
	sealed       sealedValue
}

func generateSealedSidecarKey(keyring *secrets.Keyring, engineID int64, sidecarURL string) (sealedSidecarKey, error) {
	signingKey, generateError := sidecarauth.GenerateSigningKey()
	if generateError != nil {
		return sealedSidecarKey{}, fmt.Errorf("generate sidecar signing key: %w", generateError)
	}
	associatedData := secrets.EngineSidecarKeyAssociatedData(engineID, sidecarURL, signingKey.KeyID)
	ciphertext, keyringKeyID, sealError := keyring.Seal(signingKey.SecretBytes(), associatedData)
	if sealError != nil {
		return sealedSidecarKey{}, fmt.Errorf("seal sidecar signing key: %w", sealError)
	}
	return sealedSidecarKey{
		keyID:        signingKey.KeyID,
		publicKeyHex: signingKey.PublicKeyHex(),
		sealed:       sealedValue{ciphertext: ciphertext, keyID: keyringKeyID},
	}, nil
}

func openSidecarKey(keyring *secrets.Keyring, engineID int64, sidecarURL, signingKeyID string, sealed sealedValue) (sidecarauth.SigningKey, error) {
	associatedData := secrets.EngineSidecarKeyAssociatedData(engineID, sidecarURL, signingKeyID)
	secretBytes, openError := keyring.Open(sealed.ciphertext, sealed.keyID, associatedData)
	if openError != nil {
		return sidecarauth.SigningKey{}, fmt.Errorf("open sidecar signing key: %w", openError)
	}
	signingKey, parseError := sidecarauth.ParseSigningKey(signingKeyID, secretBytes)
	if parseError != nil {
		return sidecarauth.SigningKey{}, fmt.Errorf("open sidecar signing key: %w", secrets.ErrDecrypt)
	}
	return signingKey, nil
}
