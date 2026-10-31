package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func serve(handler http.Handler, requestPath string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, requestPath, nil))
	return recorder
}

func TestSPAHandlerServesAssetAndFallsBackToIndex(testContext *testing.T) {
	handler := spaHandler(fstest.MapFS{
		"index.html":    {Data: []byte("<html>spa</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	})

	assetResponse := serve(handler, "/assets/app.js")
	if !strings.Contains(assetResponse.Body.String(), "console.log") {
		testContext.Errorf("asset not served: %q", assetResponse.Body.String())
	}

	routeResponse := serve(handler, "/decisions/list")
	if routeResponse.Code != http.StatusOK || !strings.Contains(routeResponse.Body.String(), "spa") {
		testContext.Errorf("fallback failed: %d %q", routeResponse.Code, routeResponse.Body.String())
	}
}

func TestSPAHandlerAnswersNotFoundWithoutIndex(testContext *testing.T) {
	handler := spaHandler(fstest.MapFS{".gitkeep": {}})

	response := serve(handler, "/anything")

	if response.Code != http.StatusNotFound {
		testContext.Errorf("expected 404, got %d", response.Code)
	}
}

func TestSPAHandlerAnswersNotFoundForMissingAssetsAndFiles(testContext *testing.T) {
	handler := spaHandler(fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}})

	for _, missingPath := range []string{"/assets/old-hash.js", "/assets/dir/old.css", "/favicon.ico", "/logo.png"} {
		response := serve(handler, missingPath)
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "spa") {
			testContext.Errorf("%s: expected plain 404, got %d %q", missingPath, response.Code, response.Body.String())
		}
	}
}

func TestSPAHandlerKeepsFallbackForNavigationRoutes(testContext *testing.T) {
	handler := spaHandler(fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}})

	for _, route := range []string{"/bouncers", "/config/files", "/page.html"} {
		response := serve(handler, route)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "spa") {
			testContext.Errorf("%s: fallback failed: %d", route, response.Code)
		}
	}
}
