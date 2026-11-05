package sidecarserver

import (
	"bytes"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

func TestSidecarFileReadsAreMasked(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)

	recorder := fixture.get(testContext, sidecarapi.PathFilePrefix+"config.yaml")

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	var fileResponse sidecarapi.FileResponse
	decodeStrictJSON(testContext, recorder, &fileResponse)
	obtainedContent := string(fileResponse.Content)
	if strings.Contains(obtainedContent, plantedSecret) {
		testContext.Errorf("the planted secret left the sidecar:\n%s", obtainedContent)
	}
	if !strings.Contains(obtainedContent, confread.RedactedMarker) {
		testContext.Errorf("expected the redaction marker in:\n%s", obtainedContent)
	}
	// Masking is exactly the local one: the sidecar adds no second policy.
	expectedContent, _ := confread.Read(fixture.confDir, "config.yaml")
	if obtainedContent != string(expectedContent) || fileResponse.Name != "config.yaml" {
		testContext.Errorf("expected the confread masking of config.yaml, got name %q content:\n%s", fileResponse.Name, obtainedContent)
	}

	traversalRecorder := fixture.get(testContext, sidecarapi.PathFilePrefix+"../secrets")
	expectResponse(testContext, traversalRecorder, http.StatusNotFound, codeBody(sidecarapi.CodeNotFound))
}

func TestSidecarFileReadsHideEverythingOutsideTheAllowList(testContext *testing.T) {
	// Each name either escapes ConfDir, is outside the confread allow list,
	// is a symlink, a directory, or is absent: the answer must be the same
	// 404 body for all of them, so existence never leaks.
	hiddenRequestURIs := []string{
		sidecarapi.PathFilePrefix + "../secrets",
		sidecarapi.PathFilePrefix + "%2e%2e/secrets",
		sidecarapi.PathFilePrefix + "%252e%252e/secrets",
		sidecarapi.PathFilePrefix + "acquis.d%5c..%5c..%5csecrets",
		sidecarapi.PathFilePrefix + "CONFIG.YAML",
		sidecarapi.PathFilePrefix + "..%2fsecrets",
		sidecarapi.PathFilePrefix + "acquis.d/../../secrets",
		sidecarapi.PathFilePrefix + "/etc/passwd",
		sidecarapi.PathFilePrefix + "%2Fetc%2Fpasswd",
		sidecarapi.PathFilePrefix + "secrets",
		sidecarapi.PathFilePrefix + "config.yaml.local",
		sidecarapi.PathFilePrefix + "acquis.d/credentials.yaml",
		sidecarapi.PathFilePrefix + "acquis.d/escape.yaml",
		sidecarapi.PathFilePrefix + "acquis.d/missing.yaml",
		sidecarapi.PathFilePrefix + "acquis.d",
		sidecarapi.PathFilePrefix + "config.yaml%00",
		sidecarapi.PathFilePrefix + "config.yaml/",
		sidecarapi.PathFilePrefix,
	}
	for _, hiddenRequestURI := range hiddenRequestURIs {
		testContext.Run(hiddenRequestURI, func(subtestContext *testing.T) {
			fixture := newConfigFixture(subtestContext, nil)

			recorder := fixture.get(subtestContext, hiddenRequestURI)

			expectResponse(subtestContext, recorder, http.StatusNotFound, codeBody(sidecarapi.CodeNotFound))
		})
	}
}

func TestSidecarFileListShowsOnlyAllowedRegularFiles(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)

	recorder := fixture.get(testContext, sidecarapi.PathFiles)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	var listResponse sidecarapi.FileListResponse
	decodeStrictJSON(testContext, recorder, &listResponse)
	expectedFiles := []string{"acquis.d/nginx.yaml", "config.yaml", "profiles.yaml"}
	if !slices.Equal(listResponse.Files, expectedFiles) {
		testContext.Errorf("expected files %v, got %v", expectedFiles, listResponse.Files)
	}
}

func TestSidecarFileReadRefusesFilesAboveTheCap(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)

	recorder := fixture.get(testContext, sidecarapi.PathFilePrefix+"profiles.yaml")

	expectResponse(testContext, recorder, http.StatusRequestEntityTooLarge, codeBody(sidecarapi.CodeFileTooLarge))
}

func TestSidecarFlushMaxItemsReadsTheLocalOverride(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)

	recorder := fixture.get(testContext, sidecarapi.PathFlushMaxItems)

	expectResponse(testContext, recorder, http.StatusOK, `{"max_items":300,"readable":true}`+"\n")
}

func TestSidecarConfigRoutesRequireATokenBeforeAnyFileAccess(testContext *testing.T) {
	routes := []struct {
		method     string
		requestURI string
	}{
		{http.MethodGet, sidecarapi.PathFiles},
		{http.MethodGet, sidecarapi.PathFilePrefix + "config.yaml"},
		{http.MethodGet, sidecarapi.PathFlushMaxItems},
		{http.MethodGet, sidecarapi.PathAcquisitionState},
		{http.MethodGet, sidecarapi.PathAcquisitionFilePrefix + "nginx.yaml"},
		{http.MethodPost, sidecarapi.PathConfigApply},
	}
	for _, route := range routes {
		testContext.Run(route.method+" "+route.requestURI, func(subtestContext *testing.T) {
			fixture := newConfigFixture(subtestContext, nil)
			acquisitionBefore := treeSnapshot(subtestContext, fixture.acquisitionDir)
			request := newSignedRequest(route.method, route.requestURI, "", forbiddenBodyReader{testContext: subtestContext})

			recorder := fixture.serve(request)

			expectResponse(subtestContext, recorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeInvalidToken))
			expectSameTree(subtestContext, "acquisition dir", acquisitionBefore, treeSnapshot(subtestContext, fixture.acquisitionDir))
			if obtainedArgvs := fixture.runner.argvs(); len(obtainedArgvs) != 0 {
				subtestContext.Errorf("expected nothing to run, got %v", obtainedArgvs)
			}
		})
	}
}

func TestSidecarUncleanPathWithoutATokenIsRefusedBeforeTheBodyIsRead(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	request := newSignedRequest(http.MethodGet, sidecarapi.PathFilePrefix+"../secrets", "", forbiddenBodyReader{testContext: testContext})

	recorder := fixture.serve(request)

	// Authentication runs before the clean-path check, so an anonymous
	// caller cannot probe which paths the router would answer 404 to.
	expectResponse(testContext, recorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeInvalidToken))
}

func TestSidecarFilesAreUnavailableWhenConfDirIsMissing(testContext *testing.T) {
	missingConfDir := filepath.Join(testContext.TempDir(), "absent")
	fixture := newConfigFixture(testContext, func(config *Config) { config.ConfDir = missingConfDir })

	// A missing ConfDir is a broken mount, not a missing file: the dashboard
	// must report the engine's configuration as unavailable, not as empty.
	for _, requestURI := range []string{sidecarapi.PathFiles, sidecarapi.PathFilePrefix + "config.yaml"} {
		expectResponse(testContext, fixture.get(testContext, requestURI), http.StatusServiceUnavailable, codeBody(sidecarapi.CodeConfigUnavailable))
	}
}

func TestSidecarReadRoutesAcceptOnlyAnEmptyBody(testContext *testing.T) {
	readRequestURIs := []string{
		sidecarapi.PathFiles,
		sidecarapi.PathFilePrefix + "config.yaml",
		sidecarapi.PathFlushMaxItems,
		sidecarapi.PathAcquisitionState,
		sidecarapi.PathAcquisitionFilePrefix + "nginx.yaml",
	}
	smuggledBody := []byte(`{"name":"config.yaml"}`)
	for _, readRequestURI := range readRequestURIs {
		testContext.Run(readRequestURI, func(subtestContext *testing.T) {
			fixture := newConfigFixture(subtestContext, nil)

			// A token honestly bound to a non-empty body: the body itself is
			// refused by the zero-byte cap before any file is touched.
			boundToken := fixture.sign(subtestContext, http.MethodGet, readRequestURI, smuggledBody)
			boundRecorder := fixture.serve(newSignedRequest(http.MethodGet, readRequestURI, boundToken, bytes.NewReader(smuggledBody)))
			expectResponse(subtestContext, boundRecorder, http.StatusRequestEntityTooLarge, codeBody(sidecarapi.CodeBodyTooLarge))

			// The same token without its body no longer matches its hash.
			unboundToken := fixture.sign(subtestContext, http.MethodGet, readRequestURI, smuggledBody)
			unboundRecorder := fixture.serve(newSignedRequest(http.MethodGet, readRequestURI, unboundToken, nil))
			expectResponse(subtestContext, unboundRecorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeBodyMismatch))
		})
	}
}
