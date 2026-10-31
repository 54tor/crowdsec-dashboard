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
