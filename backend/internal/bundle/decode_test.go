package bundle

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const minimalBundleHeader = `{"format":"crowdsec-dashboard-bundle","version":1,"created_at":"2026-11-03T12:00:00Z","engine_version":"v1.8.2","contains_secrets":false,`

func TestDecodeAcceptsAnEncodedBundle(testContext *testing.T) {
	exported := Bundle{Format: Format, Version: Version, Sections: Sections{Hub: &HubSection{Collections: []HubCollection{{Name: "crowdsecurity/linux", Version: "0.4"}}}}}
	encoded, encodeError := Encode(exported)
	if encodeError != nil {
		testContext.Fatal(encodeError)
	}
	decoded, decodeError := Decode(bytes.NewReader(encoded), MaxBytes)
	if decodeError != nil || decoded.Sections.Hub == nil || decoded.Sections.Hub.Collections[0].Name != "crowdsecurity/linux" {
		testContext.Errorf("expected the encoded bundle to decode back, got %+v (%v)", decoded, decodeError)
	}
}

func TestDecodeRejectsUnknownVersionSectionAndField(testContext *testing.T) {
	casesByName := map[string]struct {
		body          string
		expectedError error
	}{
		"future version":       {`{"format":"crowdsec-dashboard-bundle","version":2,"sections":{}}`, ErrVersion},
		"zero version":         {`{"format":"crowdsec-dashboard-bundle","sections":{}}`, ErrVersion},
		"foreign format":       {`{"format":"other-bundle","version":1,"sections":{}}`, ErrInvalid},
		"missing format":       {`{"version":1,"sections":{}}`, ErrInvalid},
		"unknown section":      {minimalBundleHeader + `"sections":{"peers":{}}}`, ErrInvalid},
		"unknown top field":    {minimalBundleHeader + `"sections":{},"signature":"x"}`, ErrInvalid},
		"unknown nested field": {minimalBundleHeader + `"sections":{"decisions":{"decisions":[{"value":"203.0.113.7","duration":"4h"}]}}}`, ErrInvalid},
		"trailing object":      {minimalBundleHeader + `"sections":{}}{}`, ErrInvalid},
		"not json":             {`format: yaml`, ErrInvalid},
	}
	for caseName, currentCase := range casesByName {
		_, decodeError := Decode(strings.NewReader(currentCase.body), MaxBytes)
		if !errors.Is(decodeError, currentCase.expectedError) {
			testContext.Errorf("%s: expected %v, got %v", caseName, currentCase.expectedError, decodeError)
		}
	}
}

func TestDecodeRejectsOversizedBody(testContext *testing.T) {
	// The padding sits inside a valid string so only the size limit can refuse the body.
	oversizedBody := minimalBundleHeader + `"sections":{"config":{"redacted":true,"files":[{"name":"acquis.yaml","content":"` + strings.Repeat("a", MaxBytes) + `"}]}}}`
	if _, decodeError := Decode(strings.NewReader(oversizedBody), MaxBytes); !errors.Is(decodeError, ErrTooLarge) {
		testContext.Errorf("expected ErrTooLarge above %d bytes, got %v", MaxBytes, decodeError)
	}
	smallLimit := int64(len(minimalBundleHeader))
	if _, decodeError := Decode(strings.NewReader(minimalBundleHeader+`"sections":{}}`), smallLimit); !errors.Is(decodeError, ErrTooLarge) {
		testContext.Errorf("expected the caller's limit to apply, got %v", decodeError)
	}
}

func TestDecodeRejectsDeepNesting(testContext *testing.T) {
	// Strict typing would also refuse these bodies, so the depth scan itself is asserted below:
	// it must refuse one level above the limit and a zip-bomb style depth without recursing.
	for _, nestingDepth := range []int{MaxDepth + 1, 100000} {
		nestedArrays := strings.Repeat("[", nestingDepth) + strings.Repeat("]", nestingDepth)
		if checkStructure([]byte(nestedArrays)) == nil {
			testContext.Errorf("depth %d: the depth scan must refuse it", nestingDepth)
		}
		body := minimalBundleHeader + `"sections":{},"padding":` + nestedArrays + `}`
		if _, decodeError := Decode(strings.NewReader(body), MaxBytes); !errors.Is(decodeError, ErrInvalid) {
			testContext.Errorf("depth %d: expected ErrInvalid, got %v", nestingDepth, decodeError)
		}
	}
	if checkStructure([]byte(strings.Repeat("[", MaxDepth)+strings.Repeat("]", MaxDepth))) != nil {
		testContext.Error("a document exactly at the depth limit must pass the depth scan")
	}
}
