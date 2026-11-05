package sidecarclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confwrite"
)

const acquisitionWithSecret = nginxAcquisition + "password: " + plantedSecret + "\n"

// validDigest is a well-formed lowercase HMAC-SHA256 hex digest the hostile
// sidecars use when only another field is meant to be wrong.
var validDigest = strings.Repeat("ab", sha256.Size)

func TestRemoteAcquisitionReadReturnsRedactedContentAndAKeyedDigest(testContext *testing.T) {
	sidecar := startConfigSidecar(testContext, nil)
	writeFixtureFile(testContext, filepath.Join(sidecar.acquisitionDir, "nginx.yaml"), acquisitionWithSecret)

	acquisitionFile, readError := sidecar.client.ReadAcquisitionFile(context.Background(), "nginx.yaml")

	if readError != nil || !acquisitionFile.Exists || acquisitionFile.Oversized {
		testContext.Fatalf("expected an existing file, got %+v (%v)", acquisitionFile, readError)
	}
	if strings.Contains(string(acquisitionFile.RedactedContent), plantedSecret) {
		testContext.Errorf("the planted secret reached the dashboard:\n%s", acquisitionFile.RedactedContent)
	}
	expectedContent := confread.Redact([]byte(acquisitionWithSecret))
	if string(acquisitionFile.RedactedContent) != string(expectedContent) {
		testContext.Errorf("expected the confread redaction, got:\n%s", acquisitionFile.RedactedContent)
	}
	// The digest is opaque: it must not be the plain hash the dashboard could
	// compute itself, yet the same sidecar gives it again for the same bytes.
	rawSum := sha256.Sum256([]byte(acquisitionWithSecret))
	if len(acquisitionFile.Digest) != 64 || acquisitionFile.Digest == hex.EncodeToString(rawSum[:]) {
		testContext.Errorf("expected a keyed digest, got %q", acquisitionFile.Digest)
	}
	secondRead, secondError := sidecar.client.ReadAcquisitionFile(context.Background(), "nginx.yaml")
	if secondError != nil || secondRead.Digest != acquisitionFile.Digest {
		testContext.Errorf("expected the same digest on a second read, got %q (%v)", secondRead.Digest, secondError)
	}
}

func TestRemoteAcquisitionReadRefusesInconsistentAnswers(testContext *testing.T) {
	encodedContent := base64.StdEncoding.EncodeToString([]byte(nginxAcquisition))
	oversizedContent := base64.StdEncoding.EncodeToString(make([]byte, confwrite.MaxFileBytes+1))
	inconsistentBodies := map[string]string{
		"oversized with content":    `{"exists":true,"oversized":true,"digest":"","content":"` + encodedContent + `"}`,
		"oversized with a digest":   `{"exists":true,"oversized":true,"digest":"` + validDigest + `","content":null}`,
		"absent with content":       `{"exists":false,"oversized":false,"digest":"","content":"` + encodedContent + `"}`,
		"absent with a digest":      `{"exists":false,"oversized":false,"digest":"` + validDigest + `","content":null}`,
		"absent but oversized":      `{"exists":false,"oversized":true,"digest":"","content":null}`,
		"existing without a digest": `{"exists":true,"oversized":false,"digest":"","content":"` + encodedContent + `"}`,
		"uppercase digest":          `{"exists":true,"oversized":false,"digest":"` + strings.ToUpper(validDigest) + `","content":"` + encodedContent + `"}`,
		"short digest":              `{"exists":true,"oversized":false,"digest":"abcd","content":"` + encodedContent + `"}`,
		"long digest":               `{"exists":true,"oversized":false,"digest":"` + validDigest + `a","content":"` + encodedContent + `"}`,
		"legacy plain hash field":   `{"exists":true,"oversized":false,"sha256":"` + validDigest + `","content":"` + encodedContent + `"}`,
		"non hex digest":            `{"exists":true,"oversized":false,"digest":"` + strings.Repeat("zz", sha256.Size) + `","content":"` + encodedContent + `"}`,
		"content above the cap":     `{"exists":true,"oversized":false,"digest":"` + validDigest + `","content":"` + oversizedContent + `"}`,
		"existing without content":  `{"exists":true,"oversized":false,"digest":"` + validDigest + `","content":null}`,
	}
	for caseLabel, inconsistentBody := range inconsistentBodies {
		testContext.Run(caseLabel, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(http.StatusOK, inconsistentBody))

			acquisitionFile, readError := client.ReadAcquisitionFile(context.Background(), "nginx.yaml")

			if !errors.Is(readError, ErrInvalidResponse) || acquisitionFile.RedactedContent != nil {
				subtestContext.Errorf("expected ErrInvalidResponse and no content, got %v and %+v", readError, acquisitionFile)
			}
		})
	}
}

func TestRemoteAcquisitionReadAcceptsAnEmptyExistingFile(testContext *testing.T) {
	client := startHostileSidecar(testContext, answering(http.StatusOK, `{"exists":true,"oversized":false,"digest":"`+validDigest+`","content":""}`))

	acquisitionFile, readError := client.ReadAcquisitionFile(context.Background(), "nginx.yaml")

	if readError != nil || !acquisitionFile.Exists || acquisitionFile.Digest != validDigest || len(acquisitionFile.RedactedContent) != 0 {
		testContext.Errorf("expected an existing empty file, got %+v (%v)", acquisitionFile, readError)
	}
}

func TestRemoteApplyRefusesResultsNamingInvalidFiles(testContext *testing.T) {
	answers := map[string]struct {
		status int
		body   string
	}{
		"created traversal":     {http.StatusOK, `{"created":["../escape.yaml"],"updated":[],"unchanged":[],"rolled_back":false}`},
		"updated forbidden":     {http.StatusOK, `{"created":[],"updated":["config.yaml"],"unchanged":[],"rolled_back":false}`},
		"unchanged nested":      {http.StatusOK, `{"created":[],"updated":[],"unchanged":["nested/nginx.yaml"],"rolled_back":false}`},
		"rolled back hidden":    {http.StatusUnprocessableEntity, `{"code":"config_test_failed","result":{"created":[".hidden.yaml"],"updated":[],"unchanged":[],"rolled_back":true}}`},
		"affected file escapes": {http.StatusInternalServerError, `{"code":"config_inconsistent","result":{"created":["nginx.yaml"],"updated":[],"unchanged":[],"rolled_back":false},"affected_files":["../../etc/passwd"]}`},
	}
	for caseLabel, answer := range answers {
		testContext.Run(caseLabel, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(answer.status, answer.body))

			result, applyError := client.ApplyConfig(context.Background(), []confwrite.FileChange{{Name: "nginx.yaml", Content: []byte(nginxAcquisition)}})

			isEmptyResult := len(result.Created)+len(result.Updated)+len(result.Unchanged) == 0 && !result.RolledBack
			if !errors.Is(applyError, ErrInvalidResponse) || !isEmptyResult {
				subtestContext.Errorf("expected ErrInvalidResponse and an empty result, got %v and %+v", applyError, result)
			}
		})
	}
}

func TestRemoteFileReadRefusesContentAboveTheConfreadCap(testContext *testing.T) {
	oversizedContent := base64.StdEncoding.EncodeToString(make([]byte, confread.MaxFileBytes+1))
	client := startHostileSidecar(testContext, answering(http.StatusOK, `{"name":"config.yaml","content":"`+oversizedContent+`"}`))

	content, readError := client.ReadFile(context.Background(), "config.yaml")

	if !errors.Is(readError, ErrInvalidResponse) || content != nil {
		testContext.Errorf("expected ErrInvalidResponse and no content, got %v and %d bytes", readError, len(content))
	}
}
