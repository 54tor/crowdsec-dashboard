package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/oplock"
)

// countingReader counts the bytes the handler pulled from the request body.
type countingReader struct {
	reader    io.Reader
	bytesRead atomic.Int64
}

func (counting *countingReader) Read(buffer []byte) (int, error) {
	readCount, readError := counting.reader.Read(buffer)
	counting.bytesRead.Add(int64(readCount))
	return readCount, readError
}

// While another operation holds the lock, a second import is refused before a single byte of its
// (up to 8 MiB) body is read: concurrent admin requests can no longer each hold a decoded bundle.
func TestImportTakesTheLockBeforeReadingTheBody(testContext *testing.T) {
	operationLock := oplock.New()
	release, acquired := operationLock.TryAcquire("sync")
	if !acquired {
		testContext.Fatal("the fresh lock must be free")
	}
	defer release()
	handlers := importHandlers{deps: (&importLocalEngine{}).deps(500), operationLock: operationLock, previewTimeout: importPreviewTimeout}
	body := &countingReader{reader: strings.NewReader(importBody(testContext, "preview", decisionsImportBundle("203.0.113.5"), "", ""))}
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/import", body)
	recorder := httptest.NewRecorder()

	handlers.importBundle(recorder, request)

	assertErrorResponse(testContext, "lock held", recorder, http.StatusConflict, "operation_running")
	if bytesRead := body.bytesRead.Load(); bytesRead != 0 {
		testContext.Errorf("the body must not be read while the lock is held, %d bytes were read", bytesRead)
	}
}

// The envelope stays bounded by the byte cap even now that the lock is taken first.
func TestImportStillRefusesAnOversizedEnvelope(testContext *testing.T) {
	handlers := importHandlers{deps: (&importLocalEngine{}).deps(500), operationLock: oplock.New(), previewTimeout: importPreviewTimeout}
	oversizedBody := `{"mode":"preview","sections":["hub"],"bundle":"` + strings.Repeat("a", maxImportBodyBytes) + `"}`
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/import", strings.NewReader(oversizedBody))
	recorder := httptest.NewRecorder()

	handlers.importBundle(recorder, request)

	assertErrorResponse(testContext, "oversized envelope", recorder, http.StatusRequestEntityTooLarge, "bundle_too_large")
}

// A hostile bundle made of a huge array of empty alerts is refused with the stable too-large code.
func TestImportRefusesAHostileArrayAsTooLarge(testContext *testing.T) {
	handlers := importHandlers{deps: (&importLocalEngine{}).deps(500), operationLock: oplock.New(), previewTimeout: importPreviewTimeout}
	hostileBundle := `{"alerts":[` + strings.TrimSuffix(strings.Repeat("{},", bundle.MaxArrayLength+1000), ",") + `]}`
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/import", strings.NewReader(importRawBody(testContext, "preview", hostileBundle, "", "")))
	recorder := httptest.NewRecorder()

	handlers.importBundle(recorder, request)

	assertErrorResponse(testContext, "hostile array", recorder, http.StatusRequestEntityTooLarge, "bundle_too_large")
}

// Without an operation lock the export fails closed like the import instead of dereferencing nil.
func TestExportFailsClosedWithoutLock(testContext *testing.T) {
	handlers := bundleHandlers{operationLock: nil}
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/export", strings.NewReader(`{"sections":["hub"]}`))
	recorder := httptest.NewRecorder()

	handlers.export(recorder, request)

	assertErrorResponse(testContext, "nil lock", recorder, http.StatusServiceUnavailable, "operation_lock_unavailable")
}
