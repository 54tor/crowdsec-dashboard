package engines

import (
	"bytes"
	"database/sql"
	"errors"

	"crowdsec-dashboard/internal/secrets"
)

const proxyCredentialSealedExpression = "engine_proxy_credential_sealed = ?"

func isNoRows(queryError error) bool {
	return errors.Is(queryError, sql.ErrNoRows)
}

func clearProxyChanges() []columnChange {
	return []columnChange{
		{"engine_proxy_kind = ?", nil}, {"engine_proxy_url = ?", nil},
		{proxyCredentialSealedExpression, nil}, {"engine_proxy_credential_key_id = ?", nil},
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
	credentialChanges, credentialError := repository.planProxyCredentials(currentRow, *input.Proxy, targetProxyBinding(currentRow, input), destinationChanged)
	if credentialError != nil {
		return nil, credentialError
	}
	return append(changes, credentialChanges...), nil
}

func (repository *Repository) planProxyCredentials(currentRow engineRow, proxyInput ProxyInput, targetBinding secretBinding, destinationChanged bool) ([]columnChange, error) {
	if proxyInput.ClearCredentials {
		if proxyInput.Username != nil || proxyInput.Password != nil {
			return nil, invalidField("proxy", "clear_credentials excludes username and password")
		}
		return []columnChange{{proxyCredentialSealedExpression, nil}, {"engine_proxy_credential_key_id = ?", nil}}, nil
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
		storedPayload, _, openError := openProxyCredential(repository.keyring, currentRow.secretBinding(), currentRow.storedProxyCredential())
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
	return sealedProxyCredentialChanges(repository.keyring, targetBinding, payload)
}

func sealedProxyCredentialChanges(keyring *secrets.Keyring, targetBinding secretBinding, payload proxyCredentialPayload) ([]columnChange, error) {
	sealedCredential, sealError := sealProxyCredential(keyring, targetBinding, payload)
	if sealError != nil {
		return nil, sealError
	}
	return []columnChange{
		{proxyCredentialSealedExpression, sealedCredential.ciphertext},
		{"engine_proxy_credential_key_id = ?", sealedCredential.keyID},
	}, nil
}

func (repository *Repository) planKeptProxyCredentialReseal(currentRow engineRow, input Input, plannedChanges []columnChange) ([]columnChange, error) {
	if !currentRow.hasProxyCredentials() || currentRow.ProxyCredentialKeyID == nil || touchesProxyCredential(plannedChanges) {
		return nil, nil
	}
	currentBinding, targetBinding := currentRow.secretBinding(), targetProxyBinding(currentRow, input)
	if bytes.Equal(currentBinding.proxyCredentialAssociatedData(), targetBinding.proxyCredentialAssociatedData()) {
		return nil, nil
	}
	storedPayload, _, openError := openProxyCredential(repository.keyring, currentBinding, currentRow.storedProxyCredential())
	if openError != nil {
		return nil, openError
	}
	return sealedProxyCredentialChanges(repository.keyring, targetBinding, storedPayload)
}

func touchesProxyCredential(plannedChanges []columnChange) bool {
	for _, plannedChange := range plannedChanges {
		if plannedChange.expression == proxyCredentialSealedExpression {
			return true
		}
	}
	return false
}

func targetProxyBinding(currentRow engineRow, input Input) secretBinding {
	binding := currentRow.secretBinding()
	binding.lapiURL = effectiveLAPIURL(currentRow, input)
	if input.Proxy != nil {
		binding.proxyKind, binding.proxyURL = input.Proxy.Kind, input.Proxy.URL
	}
	return binding
}

func effectiveLAPIURL(currentRow engineRow, input Input) string {
	if input.LAPIURL != "" {
		return input.LAPIURL
	}
	return currentRow.LAPIURL
}

func usesPlainHTTP(currentRow engineRow, input Input) bool {
	return parseValidatedURL(effectiveLAPIURL(currentRow, input)).Scheme == "http"
}
