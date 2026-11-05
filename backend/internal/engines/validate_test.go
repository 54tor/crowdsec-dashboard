package engines

import (
	"strings"
	"testing"
)

func TestValidateNameRejectsReservedAndInvalid(testContext *testing.T) {
	validNames := []string{"edge-1", "a", strings.Repeat("a", 32)}
	for _, validName := range validNames {
		if nameError := ValidateName(validName); nameError != nil {
			testContext.Errorf("%q must be accepted: %v", validName, nameError)
		}
	}
	invalidNames := []string{"", "Edge", "-edge", "edge_1", "local", strings.Repeat("a", 33), "edge 1"}
	for _, invalidName := range invalidNames {
		if nameError := ValidateName(invalidName); nameError == nil {
			testContext.Errorf("%q must be refused", invalidName)
		}
	}
}

func TestValidateLAPIURLRequiresHTTPSUnlessAllowed(testContext *testing.T) {
	testCases := []struct {
		rawURL            string
		allowInsecureHTTP bool
		expectAccepted    bool
	}{
		{"https://engine.example.com", false, true},
		{"https://engine.example.com:8080/base", false, true},
		{"http://engine.example.com", false, false},
		{"http://engine.example.com", true, true},
		{"https://user:topsecret@engine.example.com", false, false},
		{"https://engine.example.com/?token=abc", false, false},
		{"https://engine.example.com/#fragment", false, false},
		{"https://", false, false},
		{"ftp://engine.example.com", true, false},
		{"", false, false},
	}
	for _, testCase := range testCases {
		urlError := ValidateLAPIURL(testCase.rawURL, testCase.allowInsecureHTTP)
		if testCase.expectAccepted && urlError != nil {
			testContext.Errorf("%q must be accepted: %v", testCase.rawURL, urlError)
		}
		if !testCase.expectAccepted && urlError == nil {
			testContext.Errorf("%q must be refused", testCase.rawURL)
		}
		if urlError != nil && strings.Contains(urlError.Error(), "topsecret") {
			testContext.Errorf("error leaks URL credentials: %v", urlError)
		}
	}
}

func TestValidateSidecarURLRequiresHTTPSAndNoPath(testContext *testing.T) {
	httpError := ValidateSidecarURL("http://sidecar.example.com:8443")
	if httpError == nil || !strings.Contains(httpError.Error(), "must use https") {
		testContext.Errorf("an http sidecar URL must be refused with a must use https error, got %v", httpError)
	}
	if acceptedError := ValidateSidecarURL("https://sidecar.example.com:8443"); acceptedError != nil {
		testContext.Errorf("an https sidecar URL must be accepted: %v", acceptedError)
	}
	if pathError := ValidateSidecarURL("https://sidecar.example.com/base"); pathError == nil {
		testContext.Errorf("a sidecar URL with a path must be refused")
	}
}

func TestValidateProxyURLRejectsCredentialsPathAndWrongScheme(testContext *testing.T) {
	testCases := []struct {
		kind           string
		rawURL         string
		expectAccepted bool
	}{
		{"socks5", "socks5://proxy.example.com:1080", true},
		{"http", "http://proxy.example.com:3128", true},
		{"socks5", "http://proxy.example.com:1080", false},
		{"http", "socks5://proxy.example.com:3128", false},
		{"socks5", "socks5://proxy.example.com", false},
		{"socks5", "socks5://user:pass@proxy.example.com:1080", false},
		{"socks5", "socks5://proxy.example.com:1080/path", false},
		{"socks5", "socks5://proxy.example.com:1080?x=1", false},
		{"socks5", "socks5://proxy.example.com:1080#fragment", false},
		{"ftp", "ftp://proxy.example.com:21", false},
		{"socks5", "socks5://proxy.example.com:0", false},
		{"http", "http://proxy.example.com:65536", false},
		{"http", "http://proxy.example.com:99999", false},
		{"http", "http://proxy.example.com:65535", true},
	}
	for _, testCase := range testCases {
		proxyError := ValidateProxyURL(testCase.kind, testCase.rawURL)
		if testCase.expectAccepted && proxyError != nil {
			testContext.Errorf("%s %q must be accepted: %v", testCase.kind, testCase.rawURL, proxyError)
		}
		if !testCase.expectAccepted && proxyError == nil {
			testContext.Errorf("%s %q must be refused", testCase.kind, testCase.rawURL)
		}
	}
}

func TestNormalizedURLKeyIgnoresCaseDefaultPortAndTrailingSlash(testContext *testing.T) {
	if NormalizedURLKey("https://Peer.example.com:443/") != NormalizedURLKey("https://peer.example.com") {
		testContext.Error("equivalent URLs must share a key")
	}
	if NormalizedURLKey("https://peer.example.com:8443") == NormalizedURLKey("https://peer.example.com") {
		testContext.Error("different ports must not share a key")
	}
}
