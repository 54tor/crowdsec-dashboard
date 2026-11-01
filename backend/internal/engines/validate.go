package engines

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

const (
	ReservedLocalName = "local"
	ProxyKindSOCKS5   = "socks5"
	ProxyKindHTTP     = "http"
)

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	defaultPorts = map[string]string{"https": "443", "http": "80"}

	ErrNameInvalid  = errors.New("name is not valid")
	ErrNameReserved = errors.New("name is reserved")
)

func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%w: must match %s", ErrNameInvalid, namePattern)
	}
	if name == ReservedLocalName {
		return ErrNameReserved
	}
	return nil
}

func ValidateLAPIURL(rawURL string, allowInsecureHTTP bool) error {
	parsedURL, parseError := url.Parse(rawURL)
	if parseError != nil || parsedURL.Host == "" || parsedURL.Hostname() == "" {
		return errors.New("is not a valid absolute URL")
	}
	schemeAllowed := parsedURL.Scheme == "https" || (parsedURL.Scheme == "http" && allowInsecureHTTP)
	if !schemeAllowed {
		return errors.New("must use https unless allow_insecure_http is true")
	}
	if parsedURL.User != nil {
		return errors.New("must not contain credentials")
	}
	if parsedURL.RawQuery != "" || parsedURL.ForceQuery || parsedURL.Fragment != "" {
		return errors.New("must not contain a query or fragment")
	}
	return nil
}

func ValidateProxyURL(kind, rawURL string) error {
	expectedScheme, isKnownKind := map[string]string{ProxyKindSOCKS5: "socks5", ProxyKindHTTP: "http"}[kind]
	if !isKnownKind {
		return errors.New("proxy kind must be socks5 or http")
	}
	parsedURL, parseError := url.Parse(rawURL)
	if parseError != nil || parsedURL.Hostname() == "" || parsedURL.Port() == "" {
		return errors.New("proxy url must be an absolute URL with host and port")
	}
	if parsedURL.Scheme != expectedScheme {
		return fmt.Errorf("proxy url must use the %s scheme", expectedScheme)
	}
	if parsedURL.User != nil {
		return errors.New("proxy url must not contain credentials")
	}
	if parsedURL.Path != "" || parsedURL.RawQuery != "" || parsedURL.ForceQuery || parsedURL.Fragment != "" {
		return errors.New("proxy url must not contain a path, query or fragment")
	}
	return nil
}

func parseValidatedURL(rawURL string) *url.URL {
	parsedURL, _ := url.Parse(rawURL)
	if parsedURL == nil {
		return &url.URL{}
	}
	return parsedURL
}

func hostAndPort(parsedURL *url.URL) string {
	port := parsedURL.Port()
	if port == "" {
		port = defaultPorts[parsedURL.Scheme]
	}
	return parsedURL.Scheme + "://" + net.JoinHostPort(strings.ToLower(parsedURL.Hostname()), port)
}

func NormalizedURLKey(rawURL string) string {
	parsedURL := parseValidatedURL(rawURL)
	return hostAndPort(parsedURL) + strings.TrimRight(parsedURL.EscapedPath(), "/")
}

func destinationKey(rawURL string) string {
	return hostAndPort(parseValidatedURL(rawURL))
}
