package cscli

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

var ErrInvalidField = errors.New("invalid cscli field")

var (
	namePattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	hubNamePattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}(/[a-zA-Z0-9][a-zA-Z0-9._-]{0,63})?$`)
	idPattern       = regexp.MustCompile(`^[0-9]{1,10}$`)
	durationPattern = regexp.MustCompile(`^[0-9]{1,4}[smhd]$`)
)

type validator func(value string) error

func matching(pattern *regexp.Regexp) validator {
	return func(value string) error {
		if !pattern.MatchString(value) {
			return fmt.Errorf("%w: does not match %s", ErrInvalidField, pattern)
		}
		return nil
	}
}

var (
	validateName     = matching(namePattern)
	validateHubName  = matching(hubNamePattern)
	validateID       = matching(idPattern)
	validateDuration = matching(durationPattern)
)

func validateTarget(value string) error {
	if _, addressErr := netip.ParseAddr(value); addressErr == nil {
		return nil
	}
	if _, prefixErr := netip.ParsePrefix(value); prefixErr == nil {
		return nil
	}
	return fmt.Errorf("%w: not an IP address or CIDR", ErrInvalidField)
}
