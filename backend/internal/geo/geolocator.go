package geo

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

var (
	ErrCountryUnknown         = errors.New("geo: country unknown for address")
	ErrGeolocationUnavailable = errors.New("geo: geolocation unavailable")
)

type Geolocator interface {
	CountryCode(ctx context.Context, address netip.Addr) (string, error)
}

type Unavailable struct{}

func (Unavailable) CountryCode(context.Context, netip.Addr) (string, error) {
	return "", ErrGeolocationUnavailable
}

type chain struct {
	fallbackTimeout time.Duration
	primary         Geolocator
	fallbacks       []Geolocator
}

func NewChain(fallbackTimeout time.Duration, primary Geolocator, fallbacks ...Geolocator) Geolocator {
	return &chain{fallbackTimeout: fallbackTimeout, primary: primary, fallbacks: fallbacks}
}

func (providerChain *chain) CountryCode(ctx context.Context, address netip.Addr) (string, error) {
	countryCode, primaryError := providerChain.primary.CountryCode(ctx, address)
	if !errors.Is(primaryError, ErrCountryUnknown) {
		return countryCode, primaryError
	}
	for _, fallback := range providerChain.fallbacks {
		fallbackCountryCode, fallbackError := providerChain.askFallback(ctx, fallback, address)
		if fallbackError == nil && fallbackCountryCode != "" {
			return fallbackCountryCode, nil
		}
	}
	return "", ErrCountryUnknown
}

func (providerChain *chain) askFallback(ctx context.Context, fallback Geolocator, address netip.Addr) (string, error) {
	fallbackContext, cancelFallback := context.WithTimeout(ctx, providerChain.fallbackTimeout)
	defer cancelFallback()
	return fallback.CountryCode(fallbackContext, address)
}
