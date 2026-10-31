package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/store/storetest"
)

const enrollmentPathFragment = "/enroll"

type capturedLog struct{ lines []string }

func (sink *capturedLog) printf(format string, arguments ...any) {
	sink.lines = append(sink.lines, fmt.Sprintf(format, arguments...))
}

func (sink *capturedLog) joined() string { return strings.Join(sink.lines, "\n") }

func TestStartupLogsEnrollmentTokenOnEmptyDatabase(testContext *testing.T) {
	database := storetest.NewUnmigrated(testContext)
	sink := &capturedLog{}

	services, startupError := initialiseAccounts(context.Background(), database, sink.printf)
	if startupError != nil {
		testContext.Fatalf("startup: %v", startupError)
	}

	enrollmentRequired, requiredError := services.enrollment.Required(context.Background())
	if requiredError != nil || !enrollmentRequired {
		testContext.Fatalf("enrollment must be required: %v %v", enrollmentRequired, requiredError)
	}
	if len(sink.lines) != 1 {
		testContext.Fatalf("expected exactly one log line, got %d: %q", len(sink.lines), sink.lines)
	}
	if !strings.Contains(sink.lines[0], enrollmentPathFragment) {
		testContext.Errorf("log line must name %s: %q", enrollmentPathFragment, sink.lines[0])
	}
	if databaseURL := os.Getenv("TEST_DATABASE_URL"); strings.Contains(sink.joined(), databaseURL) {
		testContext.Error("DATABASE_URL must never be logged")
	}
	loggedToken := tokenFromLine(sink.lines[0])
	if len(loggedToken) < 40 {
		testContext.Fatalf("no token found in %q", sink.lines[0])
	}
	_, completeError := services.enrollment.Complete(context.Background(), loggedToken, "admin", "a-long-enough-password")
	if completeError != nil {
		testContext.Errorf("logged token must complete enrollment: %v", completeError)
	}
}

func TestStartupLogsNoTokenWhenAccountExists(testContext *testing.T) {
	database := storetest.New(testContext)
	repository := accounts.NewRepository(database)
	if _, createError := repository.CreateWithPasswordHash(context.Background(), "admin", "hash", "admin"); createError != nil {
		testContext.Fatalf("seed account: %v", createError)
	}
	sink := &capturedLog{}

	if _, startupError := initialiseAccounts(context.Background(), database, sink.printf); startupError != nil {
		testContext.Fatalf("startup: %v", startupError)
	}

	if len(sink.lines) != 0 {
		testContext.Errorf("nothing must be logged, got %q", sink.lines)
	}
}

func TestStartupAppliesPendingMigrations(testContext *testing.T) {
	database := storetest.NewUnmigrated(testContext)

	if _, startupError := initialiseAccounts(context.Background(), database, (&capturedLog{}).printf); startupError != nil {
		testContext.Fatalf("startup: %v", startupError)
	}

	var accountTable *string
	queryError := database.NewRaw("SELECT to_regclass('account')::text").Scan(context.Background(), &accountTable)
	if queryError != nil || accountTable == nil {
		testContext.Errorf("account table must exist after startup: %v", queryError)
	}
}

func tokenFromLine(line string) string {
	for _, field := range strings.Fields(line) {
		if len(field) >= 40 {
			return field
		}
	}
	return ""
}

func TestStartupRefusesInvalidSecretsKey(testContext *testing.T) {
	invalidKeyFile := filepath.Join(testContext.TempDir(), "secrets.key")
	if writeError := os.WriteFile(invalidKeyFile, []byte("not-a-valid-key-material"), 0o600); writeError != nil {
		testContext.Fatalf("write key file: %v", writeError)
	}

	keyring, loadError := loadSecretsKeyring(invalidKeyFile)

	if loadError == nil || keyring != nil {
		testContext.Fatalf("an invalid key must be refused, got %v", loadError)
	}
	if !strings.Contains(loadError.Error(), invalidKeyFile) {
		testContext.Errorf("error must name the key file: %v", loadError)
	}
	if strings.Contains(loadError.Error(), "not-a-valid-key-material") {
		testContext.Error("error must not contain the key content")
	}
	if _, missingError := loadSecretsKeyring(filepath.Join(testContext.TempDir(), "absent.key")); missingError == nil {
		testContext.Error("a missing key file must be refused")
	}
}
