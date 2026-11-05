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

// validHash is a well-formed lowercase SHA-256 hex digest the hostile
// sidecars use when only another field is meant to be wrong.
var validHash = strings.Repeat("ab", sha256.Size)

func TestRemoteAcquisitionReadReturnsRedactedContentAndTheRawHash(testContext *testing.T) {
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
	rawSum := sha256.Sum256([]byte(acquisitionWithSecret))
	if acquisitionFile.SHA256 != hex.EncodeToString(rawSum[:]) {
		testContext.Errorf("expected the hash of the raw bytes, got %q", acquisitionFile.SHA256)
	}
}

func TestRemoteAcquisitionReadRefusesInconsistentAnswers(testContext *testing.T) {
	encodedContent := base64.StdEncoding.EncodeToString([]byte(nginxAcquisition))
	oversizedContent := base64.StdEncoding.EncodeToString(make([]byte, confwrite.MaxFileBytes+1))
	inconsistentBodies := map[string]string{
		"oversized with content":   `{"exists":true,"oversized":true,"sha256":"","content":"` + encodedContent + `"}`,
		"oversized with a hash":    `{"exists":true,"oversized":true,"sha256":"` + validHash + `","content":null}`,
		"absent with content":      `{"exists":false,"oversized":false,"sha256":"","content":"` + encodedContent + `"}`,
		"absent with a hash":       `{"exists":false,"oversized":false,"sha256":"` + validHash + `","content":null}`,
		"absent but oversized":     `{"exists":false,"oversized":true,"sha256":"","content":null}`,
		"existing without a hash":  `{"exists":true,"oversized":false,"sha256":"","content":"` + encodedContent + `"}`,
		"uppercase hash":           `{"exists":true,"oversized":false,"sha256":"` + strings.ToUpper(validHash) + `","content":"` + encodedContent + `"}`,
		"short hash":               `{"exists":true,"oversized":false,"sha256":"abcd","content":"` + encodedContent + `"}`,
		"content above the cap":    `{"exists":true,"oversized":false,"sha256":"` + validHash + `","content":"` + oversizedContent + `"}`,
		"existing without content": `{"exists":true,"oversized":false,"sha256":"` + validHash + `","content":null}`,
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
	emptySum := sha256.Sum256(nil)
	emptyHash := hex.EncodeToString(emptySum[:])
	client := startHostileSidecar(testContext, answering(http.StatusOK, `{"exists":true,"oversized":false,"sha256":"`+emptyHash+`","content":""}`))

	acquisitionFile, readError := client.ReadAcquisitionFile(context.Background(), "nginx.yaml")

	if readError != nil || !acquisitionFile.Exists || acquisitionFile.SHA256 != emptyHash || len(acquisitionFile.RedactedContent) != 0 {
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
