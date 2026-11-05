package allowlists

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/cscli"
)

func TestCscliWriterBuildsTaskTwoCommands(testContext *testing.T) {
	runner := &recordingRunner{}
	writer := NewCscliWriter(cscli.NewLocalExecutor(runner))
	backgroundContext := context.Background()

	writeErrors := []error{
		writer.Create(backgroundContext, "trusted", "trusted hosts"),
		writer.Add(backgroundContext, "trusted", netip.MustParsePrefix("203.0.113.7/32"), "", ""),
		writer.Add(backgroundContext, "trusted", netip.MustParsePrefix("2001:db8::/48"), "12h", "office"),
		writer.Remove(backgroundContext, "trusted", netip.MustParsePrefix("203.0.113.7/32")),
		writer.Delete(backgroundContext, "trusted"),
	}

	for _, writeError := range writeErrors {
		if writeError != nil {
			testContext.Fatal(writeError)
		}
	}
	expectedArgvs := [][]string{
		{"cscli", "allowlists", "create", "trusted", "--description=trusted hosts"},
		{"cscli", "allowlists", "add", "trusted", "203.0.113.7"},
		{"cscli", "allowlists", "add", "trusted", "2001:db8::/48", "--expiration=12h", "--comment=office"},
		{"cscli", "allowlists", "remove", "trusted", "203.0.113.7"},
		{"cscli", "allowlists", "delete", "trusted"},
	}
	if !slices.EqualFunc(runner.argvs, expectedArgvs, slices.Equal) {
		testContext.Fatalf("expected %v, got %v", expectedArgvs, runner.argvs)
	}
}

func TestCscliWriterRefusesInvalidFieldsBeforeRunning(testContext *testing.T) {
	runner := &recordingRunner{}
	writer := NewCscliWriter(cscli.NewLocalExecutor(runner))

	nameError := writer.Create(context.Background(), "Bad Name", "trusted hosts")
	expirationError := writer.Add(context.Background(), "trusted", netip.MustParsePrefix("203.0.113.7/32"), "0d", "")

	requireErrorIs(testContext, nameError, ErrInvalid)
	requireErrorIs(testContext, expirationError, ErrInvalid)
	if len(runner.argvs) != 0 {
		testContext.Fatalf("an invalid field must not reach cscli, got %v", runner.argvs)
	}
}

func TestAddEntryReportsWriteFailureWithoutOutput(testContext *testing.T) {
	const outputMarker = "MARKER-CSCLI-OUTPUT"
	fixture := newServiceFixture(testContext, trustedAllowlist())
	runner := &recordingRunner{
		output:  []byte(outputMarker),
		failure: fmt.Errorf("%w: %s", cscli.ErrCscliFailed, outputMarker),
	}
	fixture.service.writers = LocalOnlyWriters(NewCscliWriter(cscli.NewLocalExecutor(runner)))

	_, addError := fixture.service.AddEntry(context.Background(), localEngineName, "trusted", EntryInput{Value: "203.0.113.7"})

	requireErrorIs(testContext, addError, ErrWriteFailed)
	requireErrorIs(testContext, addError, cscli.ErrCscliFailed)
	if strings.Contains(addError.Error(), outputMarker) {
		testContext.Fatalf("the cscli output leaked into the error: %v", addError)
	}
}

func TestCscliWriterHidesRunnerErrorDetails(testContext *testing.T) {
	runner := &recordingRunner{failure: errors.New("docker exec: context deadline exceeded")}
	writer := NewCscliWriter(cscli.NewLocalExecutor(runner))

	deleteError := writer.Delete(context.Background(), "trusted")

	requireErrorIs(testContext, deleteError, ErrWriteFailed)
	if strings.Contains(deleteError.Error(), "docker exec") {
		testContext.Fatalf("the runner error leaked into the error: %v", deleteError)
	}
}
