package cscli

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"crowdsec-dashboard/internal/netparse"
)

const maxFreeTextBytes = 256

var (
	allowlistNamePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	allowlistExpirationPattern = regexp.MustCompile(`^[1-9][0-9]{0,3}[hd]$`)
)

var (
	validateAllowlistName       = matching(allowlistNamePattern)
	validateAllowlistExpiration = matching(allowlistExpirationPattern)
)

func validateAllowlistValue(value string) error {
	prefix, parseError := netparse.ParseAllowlistValue(value)
	if parseError != nil {
		return fmt.Errorf("%w: %s", ErrInvalidField, parseError)
	}
	canonicalValue := prefix.String()
	if prefix.IsSingleIP() && !strings.Contains(value, "/") {
		canonicalValue = prefix.Addr().String()
	}
	if value != canonicalValue {
		return fmt.Errorf("%w: value is not in canonical form", ErrInvalidField)
	}
	return nil
}

func validateFreeText(value string) error {
	if len(value) < 1 || len(value) > maxFreeTextBytes {
		return fmt.Errorf("%w: text must be 1 to %d bytes", ErrInvalidField, maxFreeTextBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: text is not valid UTF-8", ErrInvalidField)
	}
	if value[0] == '-' {
		return fmt.Errorf("%w: text must not start with a dash", ErrInvalidField)
	}
	for _, character := range value {
		if unicode.In(character, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("%w: text contains a control, format or separator character", ErrInvalidField)
		}
	}
	return nil
}
