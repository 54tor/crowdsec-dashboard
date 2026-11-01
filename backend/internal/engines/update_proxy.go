package engines

import (
	"database/sql"
	"errors"
)

func isNoRows(queryError error) bool {
	return errors.Is(queryError, sql.ErrNoRows)
}

func clearProxyChanges() []columnChange {
	return []columnChange{
		{"engine_proxy_kind = ?", nil}, {"engine_proxy_url = ?", nil},
		{"engine_proxy_credential_sealed = ?", nil}, {"engine_proxy_credential_key_id = ?", nil},
	}
}

func (repository *Repository) planProxy(currentRow engineRow, input Input) ([]columnChange, error) {
	if input.RemoveProxy && input.Proxy != nil {
		return nil, invalidField("proxy", "cannot be set and removed together")
	}
	if input.RemoveProxy {
		return clearProxyChanges(), nil
	}
	if input.Proxy == nil {
		return nil, nil
	}
	if proxyError := validateProxyField(input.Proxy); proxyError != nil {
		return nil, proxyError
	}
	changes := []columnChange{{"engine_proxy_kind = ?", input.Proxy.Kind}, {"engine_proxy_url = ?", input.Proxy.URL}}
	destinationChanged := currentRow.ProxyKind == nil || *currentRow.ProxyKind != input.Proxy.Kind ||
		currentRow.ProxyURL == nil || *currentRow.ProxyURL != input.Proxy.URL
	if destinationChanged && usesPlainHTTP(currentRow, input) && input.MachinePassword == nil {
		return nil, ErrSecretRequired
	}
	credentialChanges, credentialError := repository.planProxyCredentials(currentRow, *input.Proxy, destinationChanged)
	if credentialError != nil {
		return nil, credentialError
	}
	return append(changes, credentialChanges...), nil
}

func (repository *Repository) planProxyCredentials(currentRow engineRow, proxyInput ProxyInput, destinationChanged bool) ([]columnChange, error) {
	if proxyInput.ClearCredentials {
		if proxyInput.Username != nil || proxyInput.Password != nil {
			return nil, invalidField("proxy", "clear_credentials excludes username and password")
		}
		return []columnChange{{"engine_proxy_credential_sealed = ?", nil}, {"engine_proxy_credential_key_id = ?", nil}}, nil
	}
	hasStoredCredentials := currentRow.hasProxyCredentials() && currentRow.ProxyCredentialKeyID != nil
	credentialsProvided := proxyInput.Username != nil || proxyInput.Password != nil
	if !credentialsProvided {
		if hasStoredCredentials && destinationChanged {
			return nil, ErrSecretRequired
		}
		return nil, nil
	}
	payload := proxyCredentialPayload{}
	if hasStoredCredentials && !destinationChanged {
		storedPayload, openError := openProxyCredential(repository.keyring, currentRow.ID, currentRow.ProxyCredentialBytes, *currentRow.ProxyCredentialKeyID)
		if openError != nil {
			return nil, openError
		}
		payload = storedPayload
	} else if proxyInput.Username == nil || proxyInput.Password == nil {
		if hasStoredCredentials {
			return nil, ErrSecretRequired
		}
		return nil, invalidField("proxy", "username and password must be provided together")
	}
	if proxyInput.Username != nil {
		payload.Username = *proxyInput.Username
	}
	if proxyInput.Password != nil {
		payload.Password = *proxyInput.Password
	}
	sealedCredential, sealError := sealProxyCredential(repository.keyring, currentRow.ID, payload)
	if sealError != nil {
		return nil, sealError
	}
	return []columnChange{
		{"engine_proxy_credential_sealed = ?", sealedCredential.ciphertext},
		{"engine_proxy_credential_key_id = ?", sealedCredential.keyID},
	}, nil
}

func usesPlainHTTP(currentRow engineRow, input Input) bool {
	effectiveURL := currentRow.LAPIURL
	if input.LAPIURL != "" {
		effectiveURL = input.LAPIURL
	}
	return parseValidatedURL(effectiveURL).Scheme == "http"
}
