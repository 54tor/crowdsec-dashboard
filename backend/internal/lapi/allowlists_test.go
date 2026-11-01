package lapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const allowlistFixturePath = "../../../deploy/dev/fixtures/allowlists.json"

type allowlistServer struct {
	handler      func(responseWriter http.ResponseWriter, request *http.Request)
	capturedAuth atomic.Value
	capturedKey  atomic.Value
	capturedPath atomic.Value
	capturedRaw  atomic.Value
}

func newAllowlistClient(testing *testing.T, handler func(http.ResponseWriter, *http.Request)) (*allowlistServer, *Client) {
	recorder := &allowlistServer{handler: handler}
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			responseWriter.Write([]byte(`{"token":"tok","expire":"2099-01-01T00:00:00Z"}`))
			return
		}
		recorder.capturedAuth.Store(request.Header.Get("Authorization"))
		recorder.capturedKey.Store(request.Header.Get("X-Api-Key"))
		recorder.capturedPath.Store(request.URL.Path)
		recorder.capturedRaw.Store(request.URL.RawQuery)
		recorder.handler(responseWriter, request)
	}))
	testing.Cleanup(server.Close)
	return recorder, NewClient(server.URL, "machine-1", testPassword, server.Client())
}

func serveBody(body string) func(http.ResponseWriter, *http.Request) {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Content-Type", "application/json")
		responseWriter.Write([]byte(body))
	}
}

func readAllowlistFixture(testing *testing.T) string {
	fixtureBytes, readError := os.ReadFile(allowlistFixturePath)
	if readError != nil {
		testing.Fatal(readError)
	}
	return string(fixtureBytes)
}

func TestListAllowlistsDecodesFixture(testing *testing.T) {
	_, client := newAllowlistClient(testing, serveBody(readAllowlistFixture(testing)))
	allowlistRead, listError := client.ListAllowlists(context.Background())
	if listError != nil {
		testing.Fatal(listError)
	}
	if !allowlistRead.Supported || allowlistRead.Truncated || len(allowlistRead.Allowlists) != 1 {
		testing.Fatalf("unexpected read: %+v", allowlistRead)
	}
	probeAllowlist := allowlistRead.Allowlists[0]
	if probeAllowlist.Name != "probe_allowlist" || probeAllowlist.Description != "allowlist probe" || probeAllowlist.ConsoleManaged || probeAllowlist.AllowlistID != "" {
		testing.Fatalf("unexpected allowlist: %+v", probeAllowlist)
	}
	if len(probeAllowlist.Items) != 2 || probeAllowlist.Items[0].Value != "203.0.113.50" || probeAllowlist.Items[1].Description != "valid_one_hour" {
		testing.Fatalf("unexpected items: %+v", probeAllowlist.Items)
	}
}

func TestListAllowlistsSendsWithContentAndBearer(testing *testing.T) {
	recorder, client := newAllowlistClient(testing, serveBody(`[]`))
	if _, listError := client.ListAllowlists(context.Background()); listError != nil {
		testing.Fatal(listError)
	}
	if recorder.capturedPath.Load() != "/v1/allowlists" || recorder.capturedRaw.Load() != "with_content=true" {
		testing.Fatalf("unexpected request: %v ?%v", recorder.capturedPath.Load(), recorder.capturedRaw.Load())
	}
	if recorder.capturedAuth.Load() != "Bearer tok" || recorder.capturedKey.Load() != "" {
		testing.Fatalf("unexpected credentials: %v / %v", recorder.capturedAuth.Load(), recorder.capturedKey.Load())
	}
}

func TestListAllowlistsKeepsExpirationString(testing *testing.T) {
	_, client := newAllowlistClient(testing, serveBody(readAllowlistFixture(testing)))
	allowlistRead, listError := client.ListAllowlists(context.Background())
	if listError != nil {
		testing.Fatal(listError)
	}
	items := allowlistRead.Allowlists[0].Items
	if items[0].Expiration != "0001-01-01T00:00:00.000Z" || items[1].Expiration != "2026-11-01T07:07:06.810Z" {
		testing.Fatalf("unexpected expirations: %+v", items)
	}
}

func TestListAllowlistsTreatsLAPI404AsUnsupported(testing *testing.T) {
	_, client := newAllowlistClient(testing, func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Content-Type", "application/json")
		responseWriter.WriteHeader(http.StatusNotFound)
		responseWriter.Write([]byte(`{"message":"route not found"}`))
	})
	allowlistRead, listError := client.ListAllowlists(context.Background())
	if listError != nil || allowlistRead.Supported || len(allowlistRead.Allowlists) != 0 {
		testing.Fatalf("unexpected result: %+v, %v", allowlistRead, listError)
	}
}

func TestListAllowlistsEmptyBody404FailsClosed(testing *testing.T) {
	_, client := newAllowlistClient(testing, func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header()["Content-Type"] = nil
		responseWriter.WriteHeader(http.StatusNotFound)
	})
	if _, listError := client.ListAllowlists(context.Background()); !errors.Is(listError, ErrAllowlistsUnreadable) {
		testing.Fatalf("expected ErrAllowlistsUnreadable, got %v", listError)
	}
}

func TestNonLAPI404FailsClosed(testing *testing.T) {
	notFoundBodies := map[string]struct{ contentType, body string }{
		"plain":                {"text/plain; charset=utf-8", "404 page not found"},
		"html":                 {"text/html", "<html><body>Not Found</body></html>"},
		"json-without-message": {"application/json", `{"error":"nope"}`},
		"json-numeric-message": {"application/json", `{"message":42}`},
	}
	for caseName, notFoundCase := range notFoundBodies {
		_, client := newAllowlistClient(testing, func(responseWriter http.ResponseWriter, request *http.Request) {
			responseWriter.Header().Set("Content-Type", notFoundCase.contentType)
			responseWriter.WriteHeader(http.StatusNotFound)
			responseWriter.Write([]byte(notFoundCase.body))
		})
		if _, listError := client.ListAllowlists(context.Background()); !errors.Is(listError, ErrAllowlistsUnreadable) {
			testing.Fatalf("%s: expected ErrAllowlistsUnreadable, got %v", caseName, listError)
		}
	}
}

func TestListAllowlists500IsAnErrorWithoutBody(testing *testing.T) {
	notFoundFixture, readError := os.ReadFile("../../../deploy/dev/fixtures/allowlist-not-found.json")
	if readError != nil {
		testing.Fatal(readError)
	}
	_, client := newAllowlistClient(testing, func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Content-Type", "application/json")
		responseWriter.WriteHeader(http.StatusInternalServerError)
		responseWriter.Write(notFoundFixture)
	})
	_, listError := client.ListAllowlists(context.Background())
	if listError == nil || strings.Contains(listError.Error(), "unknown_list") {
		testing.Fatalf("expected an error without body content, got %v", listError)
	}
}

func TestListAllowlistsMapsAuthFailures(testing *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		_, client := newAllowlistClient(testing, func(responseWriter http.ResponseWriter, request *http.Request) {
			http.Error(responseWriter, "denied", status)
		})
		if _, listError := client.ListAllowlists(context.Background()); !errors.Is(listError, ErrAuthFailed) {
			testing.Fatalf("status %d: expected ErrAuthFailed, got %v", status, listError)
		}
	}
}

func TestListAllowlistsFlagsTruncatedBody(testing *testing.T) {
	oversizedBody := "[" + strings.Repeat(" ", maxAllowlistResponseBytes+10) + "]"
	_, client := newAllowlistClient(testing, serveBody(oversizedBody))
	allowlistRead, listError := client.ListAllowlists(context.Background())
	if listError != nil || !allowlistRead.Truncated || len(allowlistRead.Allowlists) != 0 {
		testing.Fatalf("unexpected result: %+v, %v", allowlistRead, listError)
	}
}

func TestListAllowlistsFlagsTruncationAboveEntryCap(testing *testing.T) {
	var itemsJSON []string
	for entryNumber := 0; entryNumber < 12000; entryNumber++ {
		itemsJSON = append(itemsJSON, fmt.Sprintf(`{"value":"10.%d.%d.1","expiration":"0001-01-01T00:00:00.000Z"}`, entryNumber/250, entryNumber%250))
	}
	body := `[{"name":"big","items":[` + strings.Join(itemsJSON, ",") + `]}]`
	_, client := newAllowlistClient(testing, serveBody(body))
	allowlistRead, listError := client.ListAllowlists(context.Background())
	if listError != nil {
		testing.Fatal(listError)
	}
	if !allowlistRead.Truncated || len(allowlistRead.Allowlists[0].Items) != 10000 {
		testing.Fatalf("unexpected result: truncated=%v items=%d", allowlistRead.Truncated, len(allowlistRead.Allowlists[0].Items))
	}
}

func TestListAllowlistsErrorNeverContainsBody(testing *testing.T) {
	_, client := newAllowlistClient(testing, func(responseWriter http.ResponseWriter, request *http.Request) {
		http.Error(responseWriter, "body-must-not-leak", http.StatusInternalServerError)
	})
	_, listError := client.ListAllowlists(context.Background())
	if listError == nil || strings.Contains(listError.Error(), "body-must-not-leak") {
		testing.Fatalf("unexpected error: %v", listError)
	}
}

func serveStatusAndBody(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Content-Type", "application/json")
		responseWriter.WriteHeader(status)
		responseWriter.Write([]byte(body))
	}
}

func TestListAllowlistsUnreadableResponsesFailClosed(parentTest *testing.T) {
	paddedMessage := `{"message":"x","padding":"` + strings.Repeat("a", maxUnsupportedBodyBytes) + `"}`
	unreadableCases := []struct {
		caseName string
		status   int
		body     string
	}{
		{"200-invalid-json", http.StatusOK, `[{"name":`},
		{"200-object-instead-of-array", http.StatusOK, `{"name":"probe"}`},
		{"200-empty-body", http.StatusOK, ``},
		{"404-json-array", http.StatusNotFound, `[{"message":"x"}]`},
		{"404-body-above-4-kib", http.StatusNotFound, paddedMessage},
	}
	for _, unreadableCase := range unreadableCases {
		parentTest.Run(unreadableCase.caseName, func(subTest *testing.T) {
			_, client := newAllowlistClient(subTest, serveStatusAndBody(unreadableCase.status, unreadableCase.body))
			allowlistRead, listError := client.ListAllowlists(context.Background())
			if !errors.Is(listError, ErrAllowlistsUnreadable) {
				subTest.Fatalf("expected ErrAllowlistsUnreadable, got %v", listError)
			}
			if allowlistRead.Supported || len(allowlistRead.Allowlists) != 0 {
				subTest.Fatalf("an unreadable response must not look like a success: %+v", allowlistRead)
			}
		})
	}
}

func TestListAllowlistsEmptyBodiesAreSuccessful(parentTest *testing.T) {
	for _, emptyBody := range []string{`null`, `[]`} {
		parentTest.Run(emptyBody, func(subTest *testing.T) {
			_, client := newAllowlistClient(subTest, serveBody(emptyBody))
			allowlistRead, listError := client.ListAllowlists(context.Background())
			if listError != nil || !allowlistRead.Supported || allowlistRead.Truncated || len(allowlistRead.Allowlists) != 0 {
				subTest.Fatalf("unexpected result: %+v, %v", allowlistRead, listError)
			}
		})
	}
}

func buildAllowlistsJSON(entryCounts []int) string {
	allowlistsJSON := []string{}
	for allowlistNumber, entryCount := range entryCounts {
		itemsJSON := []string{}
		for entryNumber := 0; entryNumber < entryCount; entryNumber++ {
			itemsJSON = append(itemsJSON, fmt.Sprintf(`{"value":"10.%d.%d.1"}`, allowlistNumber, entryNumber))
		}
		allowlistsJSON = append(allowlistsJSON, fmt.Sprintf(`{"name":"list_%d","items":[%s]}`, allowlistNumber, strings.Join(itemsJSON, ",")))
	}
	return "[" + strings.Join(allowlistsJSON, ",") + "]"
}

func TestListAllowlistsEntryCapBoundary(parentTest *testing.T) {
	boundaryCases := []struct {
		caseName          string
		entryCounts       []int
		expectedTruncated bool
	}{
		{"exactly-10000-over-two-lists", []int{6000, 4000}, false},
		{"10001-over-two-lists", []int{6000, 4001}, true},
	}
	for _, boundaryCase := range boundaryCases {
		parentTest.Run(boundaryCase.caseName, func(subTest *testing.T) {
			_, client := newAllowlistClient(subTest, serveBody(buildAllowlistsJSON(boundaryCase.entryCounts)))
			allowlistRead, listError := client.ListAllowlists(context.Background())
			if listError != nil {
				subTest.Fatal(listError)
			}
			totalEntries := 0
			for _, allowlist := range allowlistRead.Allowlists {
				totalEntries += len(allowlist.Items)
			}
			if totalEntries != 10000 || allowlistRead.Truncated != boundaryCase.expectedTruncated {
				subTest.Fatalf("entries=%d truncated=%v", totalEntries, allowlistRead.Truncated)
			}
		})
	}
}

func TestListAllowlistsReturnsPromptlyWhenContextIsCancelled(testing *testing.T) {
	releaseServer := make(chan struct{})
	_, client := newAllowlistClient(testing, func(responseWriter http.ResponseWriter, request *http.Request) {
		select {
		case <-releaseServer:
		case <-request.Context().Done():
		}
	})
	testing.Cleanup(func() { close(releaseServer) })
	cancellableContext, cancelRead := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancelRead)
	outcome := make(chan error, 1)
	go func() {
		_, listError := client.ListAllowlists(cancellableContext)
		outcome <- listError
	}()
	select {
	case listError := <-outcome:
		if listError == nil {
			testing.Fatal("a cancelled read must not succeed")
		}
	case <-time.After(5 * time.Second):
		testing.Fatal("ListAllowlists did not return after cancellation")
	}
}
