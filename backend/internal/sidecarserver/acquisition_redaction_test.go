package sidecarserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

// acquisitionWithSecret is a valid acquisition file carrying the planted
// secret in the shapes an operator could write: a key, a URL credential and
// a bearer header.
const acquisitionWithSecret = "source: file\nfilenames: [/var/log/nginx/access.log]\nlabels: {type: nginx}\n" +
	"password: hunter2\nforward_url: https://alice:hunter2@logs.example.com/push\nheaders:\n  Authorization: Bearer hunter2\n"

func rawHashOf(content string) string {
	rawSum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(rawSum[:])
}

func TestSidecarAcquisitionReadNeverReturnsTheRawSecret(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "nginx.yaml"), acquisitionWithSecret)

	recorder := fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"nginx.yaml")

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	// The raw body is checked before decoding: the secret must not appear
	// in any field, base64 or not, so the plain and base64 forms are both
	// searched.
	rawBody := recorder.Body.String()
	var fileResponse sidecarapi.AcquisitionFileResponse
	decodeStrictJSON(testContext, recorder, &fileResponse)
	obtainedContent := string(fileResponse.Content)
	if strings.Contains(rawBody, plantedSecret) || strings.Contains(obtainedContent, plantedSecret) {
		testContext.Errorf("the planted secret left the sidecar:\n%s", obtainedContent)
	}
	expectedContent := string(confread.Redact([]byte(acquisitionWithSecret)))
	if obtainedContent != expectedContent || !strings.Contains(obtainedContent, confread.RedactedMarker) {
		testContext.Errorf("expected the confread redaction, got:\n%s", obtainedContent)
	}
	// The digest is keyed: a plain hash of the raw bytes would let anyone
	// holding the response confirm a guessed secret offline.
	if fileResponse.Digest == "" || fileResponse.Digest == rawHashOf(acquisitionWithSecret) {
		testContext.Errorf("expected a keyed digest, got %q", fileResponse.Digest)
	}
	if !fileResponse.Exists || fileResponse.Oversized {
		testContext.Errorf("expected an existing file within the cap, got %+v", fileResponse)
	}
}

func TestSidecarAcquisitionRedactionIsIdempotent(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "nginx.yaml"), acquisitionWithSecret)
	firstRecorder := fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"nginx.yaml")
	var firstResponse sidecarapi.AcquisitionFileResponse
	decodeStrictJSON(testContext, firstRecorder, &firstResponse)

	// Writing the redacted text back and reading it again must change
	// nothing: a dashboard diffing redacted against redacted text never sees
	// a phantom change caused by the masking itself.
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "nginx.yaml"), string(firstResponse.Content))
	secondRecorder := fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"nginx.yaml")
	var secondResponse sidecarapi.AcquisitionFileResponse
	decodeStrictJSON(testContext, secondRecorder, &secondResponse)

	if string(secondResponse.Content) != string(firstResponse.Content) {
		testContext.Errorf("expected the redaction to be idempotent:\nfirst  %q\nsecond %q", firstResponse.Content, secondResponse.Content)
	}
	// The raw bytes did change (the secret became the marker), so the digest
	// of the raw bytes must change even though the redacted text did not.
	if secondResponse.Digest == firstResponse.Digest {
		testContext.Errorf("expected the digest to follow the raw bytes, got %q twice", secondResponse.Digest)
	}
}

func TestSidecarAcquisitionReadOfAnOversizedFileCarriesNoContentNorDigest(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	oversizedContent := "source: file\n#" + strings.Repeat("x", 256<<10) + "\npassword: " + plantedSecret + "\n"
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "big.yaml"), oversizedContent)

	recorder := fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"big.yaml")

	expectResponse(testContext, recorder, http.StatusOK, `{"exists":true,"oversized":true,"digest":"","content":null}`+"\n")
}

func TestSidecarApplyAnswersBusyBeforeReadingTheBody(testContext *testing.T) {
	executionStarted := make(chan struct{})
	releaseExecution := make(chan struct{})
	blockingExecutor := executorFunc(func(context.Context, string, map[string]string) ([]byte, error) {
		close(executionStarted)
		<-releaseExecution
		return []byte("done"), nil
	})
	singleSlotConfig := Config{AllowedCommands: cscli.Names(), MaxConcurrentExecutions: 1, AcquisitionDir: testContext.TempDir()}
	fixture := newFixtureServing(testContext, blockingExecutor, singleSlotConfig)
	firstRequest := fixture.signedExecRequest(testContext, context.Background(), execBody(testContext, "version", nil))
	firstRecorderReady := make(chan *httptest.ResponseRecorder)
	go func() {
		firstRecorderReady <- fixture.serve(firstRequest)
	}()
	<-executionStarted

	// The token is valid for its declared body, but the slot is taken: the
	// sidecar must answer busy without reading a single byte of the body.
	applyToken := fixture.sign(testContext, http.MethodPost, sidecarapi.PathConfigApply, applyBody(testContext, map[string]string{"nginx.yaml": nginxAcquisition}))
	busyRecorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathConfigApply, applyToken, forbiddenBodyReader{testContext: testContext}))

	expectResponse(testContext, busyRecorder, http.StatusServiceUnavailable, codeBody(sidecarapi.CodeBusy))
	close(releaseExecution)
	<-firstRecorderReady
}
