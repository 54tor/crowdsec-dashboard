package engines

import (
	"encoding/json"
	"fmt"

	"crowdsec-dashboard/internal/secrets"
)

type proxyCredentialPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sealedValue struct {
	ciphertext []byte
	keyID      string
}

type secretBinding struct {
	engineID  int64
	lapiURL   string
	proxyKind string
	proxyURL  string
}

func (row engineRow) secretBinding() secretBinding {
	binding := secretBinding{engineID: row.ID, lapiURL: row.LAPIURL}
	if row.ProxyKind != nil && row.ProxyURL != nil {
		binding.proxyKind, binding.proxyURL = *row.ProxyKind, *row.ProxyURL
	}
	return binding
}

func (binding secretBinding) machinePasswordAssociatedData() []byte {
	return secrets.EngineMachinePasswordAssociatedData(binding.engineID, binding.lapiURL)
}

func (binding secretBinding) proxyCredentialAssociatedData() []byte {
	return secrets.EngineProxyCredentialAssociatedData(binding.engineID, binding.lapiURL, binding.proxyKind, binding.proxyURL)
}

func sealMachinePassword(keyring *secrets.Keyring, binding secretBinding, password string) (sealedValue, error) {
	ciphertext, keyID, sealError := keyring.Seal([]byte(password), binding.machinePasswordAssociatedData())
	if sealError != nil {
		return sealedValue{}, fmt.Errorf("seal machine password: %w", sealError)
	}
	return sealedValue{ciphertext: ciphertext, keyID: keyID}, nil
}

func sealProxyCredential(keyring *secrets.Keyring, binding secretBinding, payload proxyCredentialPayload) (sealedValue, error) {
	encoded, marshalError := json.Marshal(payload)
	if marshalError != nil {
		return sealedValue{}, fmt.Errorf("encode proxy credential: %w", marshalError)
	}
	ciphertext, keyID, sealError := keyring.Seal(encoded, binding.proxyCredentialAssociatedData())
	if sealError != nil {
		return sealedValue{}, fmt.Errorf("seal proxy credential: %w", sealError)
	}
	return sealedValue{ciphertext: ciphertext, keyID: keyID}, nil
}

func openMachinePassword(keyring *secrets.Keyring, binding secretBinding, sealed sealedValue) (string, bool, error) {
	plaintext, isLegacyForm, openError := openWithLegacyFallback(keyring, sealed,
		binding.machinePasswordAssociatedData(), secrets.LegacyEngineMachinePasswordAssociatedData(binding.engineID))
	if openError != nil {
		return "", false, fmt.Errorf("open machine password: %w", openError)
	}
	return string(plaintext), isLegacyForm, nil
}

func openProxyCredential(keyring *secrets.Keyring, binding secretBinding, sealed sealedValue) (proxyCredentialPayload, bool, error) {
	plaintext, isLegacyForm, openError := openWithLegacyFallback(keyring, sealed,
		binding.proxyCredentialAssociatedData(), secrets.LegacyEngineProxyCredentialAssociatedData(binding.engineID))
	if openError != nil {
		return proxyCredentialPayload{}, false, fmt.Errorf("open proxy credential: %w", openError)
	}
	var payload proxyCredentialPayload
	if unmarshalError := json.Unmarshal(plaintext, &payload); unmarshalError != nil {
		return proxyCredentialPayload{}, false, fmt.Errorf("decode proxy credential: %w", secrets.ErrDecrypt)
	}
	return payload, isLegacyForm, nil
}

func openWithLegacyFallback(keyring *secrets.Keyring, sealed sealedValue, associatedData, legacyAssociatedData []byte) ([]byte, bool, error) {
	plaintext, openError := keyring.Open(sealed.ciphertext, sealed.keyID, associatedData)
	if openError == nil {
		return plaintext, false, nil
	}
	legacyPlaintext, legacyError := keyring.Open(sealed.ciphertext, sealed.keyID, legacyAssociatedData)
	if legacyError != nil {
		return nil, false, openError
	}
	return legacyPlaintext, true, nil
}
