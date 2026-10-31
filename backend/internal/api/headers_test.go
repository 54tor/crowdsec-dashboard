package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func getPath(handler http.Handler, requestPath string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://dashboard.example.com"+requestPath, nil))
	return recorder
}

func TestApiResponsesAreNotCacheable(testContext *testing.T) {
	handler := newTestHandler(testContext)
	for _, requestPath := range []string{"/api/healthz", "/api/auth/me", "/api/config/files/acquis.yaml"} {
		recorder := getPath(handler, requestPath)
		if recorder.Header().Get("Cache-Control") != "no-store" {
			testContext.Errorf("%s: expected no-store, got %q (status %d)", requestPath, recorder.Header().Get("Cache-Control"), recorder.Code)
		}
	}
}

func TestStaticResponsesAreNotMarkedNoStore(testContext *testing.T) {
	handler := newTestHandler(testContext)
	for _, requestPath := range []string{"/", "/assets/app.js"} {
		if cacheControl := getPath(handler, requestPath).Header().Get("Cache-Control"); cacheControl == "no-store" {
			testContext.Errorf("%s must not be no-store", requestPath)
		}
	}
}
