package sidecarserver

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/sidecarapi"
)

// keyedDigestPattern is the shape of a hex HMAC-SHA256: lowercase, 64 chars.
var keyedDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// readAcquisitionDigest writes content as nginx.yaml in the fixture's
// acquisition dir, reads it back through the route and returns the digest,
// failing the test on anything but a readable 200.
func readAcquisitionDigest(testContext *testing.T, fixture configFixture, content string) string {
	testContext.Helper()
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "nginx.yaml"), content)
	recorder := fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"nginx.yaml")
	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	var fileResponse sidecarapi.AcquisitionFileResponse
	decodeStrictJSON(testContext, recorder, &fileResponse)
	if !keyedDigestPattern.MatchString(fileResponse.Digest) {
		testContext.Fatalf("expected a lowercase 64-char hex digest, got %q", fileResponse.Digest)
	}
	return fileResponse.Digest
}

func TestSidecarAcquisitionDigestIsStableAcrossRequestsAndRestarts(testContext *testing.T) {
	dataDir := secureDataDir(testContext)
	firstFixture := newConfigFixtureWithDigestKey(testContext, nil, loadDigestKeyOrFail(testContext, dataDir))

	firstDigest := readAcquisitionDigest(testContext, firstFixture, acquisitionWithSecret)
	repeatedDigest := readAcquisitionDigest(testContext, firstFixture, acquisitionWithSecret)
	// A restart loads the same key file into a brand new handler.
	restartedFixture := newConfigFixtureWithDigestKey(testContext, nil, loadDigestKeyOrFail(testContext, dataDir))
	restartedDigest := readAcquisitionDigest(testContext, restartedFixture, acquisitionWithSecret)

	if firstDigest != repeatedDigest || firstDigest != restartedDigest {
		testContext.Errorf("expected one digest for one content, got %q, %q and %q", firstDigest, repeatedDigest, restartedDigest)
	}
}

func TestSidecarAcquisitionDigestDependsOnTheKey(testContext *testing.T) {
	firstSidecar := newConfigFixtureWithDigestKey(testContext, nil, loadDigestKeyOrFail(testContext, secureDataDir(testContext)))
	otherSidecar := newConfigFixtureWithDigestKey(testContext, nil, loadDigestKeyOrFail(testContext, secureDataDir(testContext)))

	firstDigest := readAcquisitionDigest(testContext, firstSidecar, acquisitionWithSecret)
	otherDigest := readAcquisitionDigest(testContext, otherSidecar, acquisitionWithSecret)

	if firstDigest == otherDigest {
		testContext.Errorf("two sidecars with different keys gave the same digest %q", firstDigest)
	}
}

func TestSidecarAcquisitionDigestChangesWithASingleByte(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	originalDigest := readAcquisitionDigest(testContext, fixture, acquisitionWithSecret)
	// One character of the secret differs: the digest must tell the files apart
	// although the redacted text is identical for both.
	alteredContent := strings.Replace(acquisitionWithSecret, "password: hunter2", "password: hunter3", 1)

	alteredDigest := readAcquisitionDigest(testContext, fixture, alteredContent)

	if originalDigest == alteredDigest {
		testContext.Errorf("a one-byte change kept the digest %q", originalDigest)
	}
}

// An attacker holding the response must find no unkeyed hash to test secret
// guesses against: neither of the raw bytes nor of the redacted text, in hex
// or base64.
func TestSidecarAcquisitionResponseCarriesNoPlainHashOfTheContent(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "nginx.yaml"), acquisitionWithSecret)

	recorder := fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"nginx.yaml")

	rawBody := recorder.Body.String()
	redactedContent := string(confread.Redact([]byte(acquisitionWithSecret)))
	for _, hashedContent := range []string{acquisitionWithSecret, redactedContent} {
		plainHashHex := rawHashOf(hashedContent)
		plainHashBytes, _ := hex.DecodeString(plainHashHex)
		if strings.Contains(rawBody, plainHashHex) || strings.Contains(rawBody, base64.StdEncoding.EncodeToString(plainHashBytes)) {
			testContext.Errorf("the response carries a plain SHA-256 of the content:\n%s", rawBody)
		}
	}
	if strings.Contains(rawBody, `"sha256"`) {
		testContext.Errorf("the response still names a sha256 field:\n%s", rawBody)
	}
}

// The key file is copied under a readable name into both served trees and
// its own name is requested: no route may return it, and no log line may
// carry it.
func TestSidecarNeverServesNorLogsTheDigestKey(testContext *testing.T) {
	dataDir := secureDataDir(testContext)
	digestKey := loadDigestKeyOrFail(testContext, dataDir)
	fixture := newConfigFixtureWithDigestKey(testContext, nil, digestKey)
	keyBytes := readDigestKeyFile(testContext, dataDir)
	for _, servedDir := range []string{fixture.acquisitionDir, fixture.confDir} {
		if writeError := os.WriteFile(filepath.Join(servedDir, "digest.key"), keyBytes, 0o600); writeError != nil {
			testContext.Fatalf("plant key copy: %v", writeError)
		}
	}
	requestedPaths := []string{
		sidecarapi.PathAcquisitionFilePrefix + "digest.key",
		sidecarapi.PathAcquisitionFilePrefix + "..%2f..%2fdigest.key",
		sidecarapi.PathAcquisitionState,
		sidecarapi.PathFiles,
		sidecarapi.PathFilePrefix + "digest.key",
	}
	readAcquisitionDigest(testContext, fixture, acquisitionWithSecret)

	keyForms := []string{string(keyBytes), hex.EncodeToString(keyBytes), base64.StdEncoding.EncodeToString(keyBytes)}
	for _, requestedPath := range requestedPaths {
		recorder := fixture.get(testContext, requestedPath)
		for _, keyForm := range keyForms {
			if strings.Contains(recorder.Body.String(), keyForm) {
				testContext.Errorf("%s returned the digest key", requestedPath)
			}
		}
	}
	for _, keyForm := range keyForms {
		if strings.Contains(fixture.logOutput.String(), keyForm) {
			testContext.Errorf("the digest key reached the log:\n%s", fixture.logOutput.String())
		}
	}
}

// A handler built without a key must refuse to answer rather than fall back
// to an unkeyed hash.
func TestSidecarAcquisitionReadWithoutADigestKeyIsUnavailable(testContext *testing.T) {
	fixture := newConfigFixtureWithDigestKey(testContext, nil, DigestKey{})
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "nginx.yaml"), acquisitionWithSecret)

	recorder := fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"nginx.yaml")

	expectResponse(testContext, recorder, http.StatusServiceUnavailable, codeBody(sidecarapi.CodeAcquisitionUnavailable))
}
