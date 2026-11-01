package engines

import (
	"encoding/json"
	"fmt"
	"strconv"

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

func machinePasswordAssociatedData(engineID int64) []byte {
	return []byte("engine.machine_password:" + strconv.FormatInt(engineID, 10))
}

func proxyCredentialAssociatedData(engineID int64) []byte {
	return []byte("engine.proxy_credential:" + strconv.FormatInt(engineID, 10))
}

func sealMachinePassword(keyring *secrets.Keyring, engineID int64, password string) (sealedValue, error) {
	ciphertext, keyID, sealError := keyring.Seal([]byte(password), machinePasswordAssociatedData(engineID))
	if sealError != nil {
		return sealedValue{}, fmt.Errorf("seal machine password: %w", sealError)
	}
	return sealedValue{ciphertext: ciphertext, keyID: keyID}, nil
}

func sealProxyCredential(keyring *secrets.Keyring, engineID int64, payload proxyCredentialPayload) (sealedValue, error) {
	encoded, marshalError := json.Marshal(payload)
	if marshalError != nil {
		return sealedValue{}, fmt.Errorf("encode proxy credential: %w", marshalError)
	}
	ciphertext, keyID, sealError := keyring.Seal(encoded, proxyCredentialAssociatedData(engineID))
	if sealError != nil {
		return sealedValue{}, fmt.Errorf("seal proxy credential: %w", sealError)
	}
	return sealedValue{ciphertext: ciphertext, keyID: keyID}, nil
}

func openProxyCredential(keyring *secrets.Keyring, engineID int64, ciphertext []byte, keyID string) (proxyCredentialPayload, error) {
	plaintext, openError := keyring.Open(ciphertext, keyID, proxyCredentialAssociatedData(engineID))
	if openError != nil {
		return proxyCredentialPayload{}, fmt.Errorf("open proxy credential: %w", openError)
	}
	var payload proxyCredentialPayload
	if unmarshalError := json.Unmarshal(plaintext, &payload); unmarshalError != nil {
		return proxyCredentialPayload{}, fmt.Errorf("decode proxy credential: %w", secrets.ErrDecrypt)
	}
	return payload, nil
}
