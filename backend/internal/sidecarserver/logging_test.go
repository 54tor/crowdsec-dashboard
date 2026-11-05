package sidecarserver

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

type loggedRecord struct {
	Message   string `json:"msg"`
	RequestID string `json:"request_id"`
	Command   string `json:"command"`
	Code      string `json:"code"`
	Status    int    `json:"status"`
}

func readLoggedRecords(testContext *testing.T, logOutput *bytes.Buffer) []loggedRecord {
	testContext.Helper()
	var records []loggedRecord
	for _, logLine := range strings.Split(strings.TrimSpace(logOutput.String()), "\n") {
		if logLine == "" {
			continue
		}
		var record loggedRecord
		if decodeError := json.Unmarshal([]byte(logLine), &record); decodeError != nil {
			testContext.Fatalf("decode log line %q: %v", logLine, decodeError)
		}
		records = append(records, record)
	}
	return records
}

func recordsWithMessage(records []loggedRecord, message string) []loggedRecord {
	var matchingRecords []loggedRecord
	for _, record := range records {
		if record.Message == message {
			matchingRecords = append(matchingRecords, record)
		}
	}
	return matchingRecords
}

func expectRequestID(testContext *testing.T, record loggedRecord) {
	testContext.Helper()
	decodedIdentifier, decodeError := hex.DecodeString(record.RequestID)
	if decodeError != nil || len(decodedIdentifier) != requestIDByteCount {
		testContext.Errorf("expected a %d-byte hex request id, got %q", requestIDByteCount, record.RequestID)
	}
}

func TestSidecarLogsCarryNoTokenFieldsOrOutput(testContext *testing.T) {
	machineOutput := []byte("password: s3cr3t-value")
	executor := newRecordingExecutor(machineOutput)
	fixture := newFixtureServing(testContext, executor, execConfigAllowingEveryCommand())
	body := execBody(testContext, "machines_add", map[string]string{"name": "alice-machine"})
	token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathExec, body)

	recorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathExec, token, bytes.NewReader(body)))

	// The secret must reach the caller: only the log has to stay clean.
	if obtainedOutput := decodeExecOutput(testContext, recorder); !bytes.Equal(obtainedOutput, machineOutput) {
		testContext.Fatalf("expected the machine output in the response, got %q", obtainedOutput)
	}
	logText := fixture.logOutput.String()
	forbiddenFragments := []string{token, fixture.signingKey.KeyID, "alice-machine", "s3cr3t-value", base64.StdEncoding.EncodeToString(machineOutput)}
	for _, forbiddenFragment := range forbiddenFragments {
		if strings.Contains(logText, forbiddenFragment) {
			testContext.Errorf("log carries %q: %s", forbiddenFragment, logText)
		}
	}
	execRecords := recordsWithMessage(readLoggedRecords(testContext, fixture.logOutput), "sidecar_exec")
	if len(execRecords) != 1 {
		testContext.Fatalf("expected one sidecar_exec line, got %s", logText)
	}
	if execRecords[0].Command != "machines_add" || execRecords[0].Status != http.StatusOK || execRecords[0].Code != "" {
		testContext.Errorf("unexpected sidecar_exec line %+v", execRecords[0])
	}
	expectRequestID(testContext, execRecords[0])
}

func TestExecLogNeverEchoesAnUnknownCommandName(testContext *testing.T) {
	fixture := newFixtureServing(testContext, newRecordingExecutor(nil), execConfigAllowingEveryCommand())

	fixture.postExec(testContext, execBody(testContext, "injected\nfake_line", nil))

	if strings.Contains(fixture.logOutput.String(), "injected") {
		testContext.Errorf("log echoes the unknown command name: %s", fixture.logOutput.String())
	}
	execRecords := recordsWithMessage(readLoggedRecords(testContext, fixture.logOutput), "sidecar_exec")
	if len(execRecords) != 1 || execRecords[0].Code != sidecarapi.CodeUnknownCommand || execRecords[0].Command != "" {
		testContext.Errorf("expected one unknown_command line without a name, got %+v", execRecords)
	}
}

func TestBodyRefusalsAreLoggedWithRequestIDAndCode(testContext *testing.T) {
	refusalCases := []struct {
		caseName        string
		path            string
		signedBody      []byte
		sentBody        []byte
		expectedMessage string
		expectedCode    string
	}{
		{"exec body mismatch", sidecarapi.PathExec, []byte(`{"command":"version"}`), []byte(`{"command":"hub_update"}`), "sidecar_exec", sidecarauth.CodeBodyMismatch},
		{"exec body above the cap", sidecarapi.PathExec, bytes.Repeat([]byte("a"), execBodyLimit+1), bytes.Repeat([]byte("a"), execBodyLimit+1), "sidecar_exec", sidecarapi.CodeBodyTooLarge},
		{"ping body mismatch", sidecarapi.PathPing, []byte("signed"), []byte("sent"), "sidecar_body_refused", sidecarauth.CodeBodyMismatch},
		{"ping body above the cap", sidecarapi.PathPing, bytes.Repeat([]byte("a"), pingBodyLimit+1), bytes.Repeat([]byte("a"), pingBodyLimit+1), "sidecar_body_refused", sidecarapi.CodeBodyTooLarge},
	}
	for _, refusalCase := range refusalCases {
		testContext.Run(refusalCase.caseName, func(caseContext *testing.T) {
			fixture := newFixtureServing(caseContext, newRecordingExecutor(nil), execConfigAllowingEveryCommand())
			token := fixture.sign(caseContext, http.MethodPost, refusalCase.path, refusalCase.signedBody)

			fixture.serve(newSignedRequest(http.MethodPost, refusalCase.path, token, bytes.NewReader(refusalCase.sentBody)))

			matchingRecords := recordsWithMessage(readLoggedRecords(caseContext, fixture.logOutput), refusalCase.expectedMessage)
			if len(matchingRecords) != 1 || matchingRecords[0].Code != refusalCase.expectedCode {
				caseContext.Fatalf("expected one %s line with code %s, got %s", refusalCase.expectedMessage, refusalCase.expectedCode, fixture.logOutput.String())
			}
			expectRequestID(caseContext, matchingRecords[0])
		})
	}
}

func TestPreAuthenticationFloodIsThrottledAndSparesTheRateLimit(testContext *testing.T) {
	executor := newRecordingExecutor([]byte("v1.7.0"))
	fixture := newFixtureServing(testContext, executor, execConfigAllowingEveryCommand())
	floodCount := refusalLogBurst * 5

	for range floodCount {
		recorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathExec, "", nil))
		expectResponse(testContext, recorder, http.StatusUnauthorized, codeBody(sidecarauth.CodeInvalidToken))
	}

	// The refusal log refills 10 lines per second; the loop takes far less
	// than a second, so the margin of 5 only absorbs a slow machine.
	refusalRecords := recordsWithMessage(readLoggedRecords(testContext, fixture.logOutput), "sidecar_auth_refused")
	if len(refusalRecords) == 0 || len(refusalRecords) > refusalLogBurst+5 {
		testContext.Errorf("expected between 1 and %d refusal lines for %d refusals, got %d", refusalLogBurst+5, floodCount, len(refusalRecords))
	}

	// Unauthenticated requests never consume the authenticated request budget.
	recorder := fixture.postExec(testContext, execBody(testContext, "version", nil))
	if obtainedOutput := decodeExecOutput(testContext, recorder); string(obtainedOutput) != "v1.7.0" {
		testContext.Errorf("expected v1.7.0 after the flood, got %q", obtainedOutput)
	}
}
