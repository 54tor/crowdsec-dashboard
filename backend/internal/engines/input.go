package engines

import (
	"encoding/json"
	"errors"

	"crowdsec-dashboard/internal/netparse"
)

func validateLAPIURLField(rawURL string, allowInsecureHTTP bool) error {
	if urlError := ValidateLAPIURL(rawURL, allowInsecureHTTP); urlError != nil {
		return invalidField("lapi_url", urlError.Error())
	}
	return nil
}

func validateProxyField(proxyInput *ProxyInput) error {
	if proxyError := ValidateProxyURL(proxyInput.Kind, proxyInput.URL); proxyError != nil {
		return invalidField("proxy", proxyError.Error())
	}
	return nil
}

func validateNameField(name string) error {
	nameError := ValidateName(name)
	if errors.Is(nameError, ErrNameReserved) {
		return invalidField("name", "is reserved")
	}
	if nameError != nil {
		return invalidField("name", "must match "+namePattern.String())
	}
	return nil
}

func canonicalPublicAddresses(rawAddresses []string) (string, error) {
	canonicalAddresses := make([]string, 0, len(rawAddresses))
	for _, rawAddress := range rawAddresses {
		address, parseError := netparse.ParseAddr(rawAddress)
		if parseError != nil {
			return "", invalidField("public_addresses", "contains an invalid address")
		}
		canonicalAddresses = append(canonicalAddresses, address.String())
	}
	encodedAddresses, marshalError := json.Marshal(canonicalAddresses)
	if marshalError != nil {
		return "", marshalError
	}
	return string(encodedAddresses), nil
}

func validateCreateInput(input Input) (string, error) {
	if nameError := validateNameField(input.Name); nameError != nil {
		return "", nameError
	}
	allowInsecureHTTP := input.AllowInsecureHTTP != nil && *input.AllowInsecureHTTP
	if urlError := validateLAPIURLField(input.LAPIURL, allowInsecureHTTP); urlError != nil {
		return "", urlError
	}
	if input.MachineID == "" {
		return "", invalidField("machine_id", "is required")
	}
	if input.MachinePassword == nil || *input.MachinePassword == "" {
		return "", invalidField("machine_password", "is required")
	}
	if input.Proxy != nil {
		if proxyError := validateProxyField(input.Proxy); proxyError != nil {
			return "", proxyError
		}
		if input.Proxy.ClearCredentials {
			return "", invalidField("proxy", "clear_credentials is not valid on creation")
		}
		hasUsername := input.Proxy.Username != nil
		hasPassword := input.Proxy.Password != nil
		if hasUsername != hasPassword {
			return "", invalidField("proxy", "username and password must be provided together")
		}
	}
	publicAddresses := []string{}
	if input.PublicAddresses != nil {
		publicAddresses = *input.PublicAddresses
	}
	return canonicalPublicAddresses(publicAddresses)
}
