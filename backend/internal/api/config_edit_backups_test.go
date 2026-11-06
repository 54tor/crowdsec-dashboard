package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/configbackups"
)

// leakedDriverSecret stands for a value PostgreSQL may echo back in an error
// message, such as the content parameter of the failed insert.
const leakedDriverSecret = "password: hunter2-from-the-insert-parameter"

// echoingBackupStore refuses every insert with an error whose text carries
// the content, the way a database driver can quote the offending parameter.
type echoingBackupStore struct{ configbackups.Store }

func (echoingBackupStore) Add(context.Context, configbackups.Backup) error {
	return errors.New("pq: value too long: " + leakedDriverSecret)
}

func TestConfigBackupFailureLogNeverCarriesTheDriverMessage(testContext *testing.T) {
	capturedLog := captureLogs(testContext)
	fixture := newConfigEditFixture(testContext)
	failingServices := NewServices(nil, &scriptedExecutor{outputsByName: map[string]string{}}, "")
	failingServices.ConfigEditor = NewLocalConfigEditor(fixture.confDir, passingLocalConfigTest)
	failingServices.ConfigBackups = echoingBackupStore{Store: configbackups.NewMemoryStore()}
	failingServices.Audit = fixture.recorder
	handler, sessions := newTestHandlerAndSessions(testContext, failingServices, localMachineID)
	fixture.handler, fixture.cookie = handler, newAuthenticatedCookie(testContext, sessions, testAccountID)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)

	response := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName, map[string]string{"content": editedFileNewUser, "expected_digest": fixture.currentDigest(testContext, editedFileName)})

	if response.Code != http.StatusOK {
		testContext.Fatalf("the save must stay applied, got %d %s", response.Code, response.Body.String())
	}
	logObtained := capturedLog.String()
	// The operator still learns which file lost its backup and the kind of failure.
	if !strings.Contains(logObtained, "config backup not stored") || !strings.Contains(logObtained, editedFileName) {
		testContext.Errorf("the failure must be logged with its file, got %q", logObtained)
	}
	if strings.Contains(logObtained, "hunter2") || strings.Contains(logObtained, "value too long") {
		testContext.Errorf("the driver message must never be logged, got %q", logObtained)
	}
}
