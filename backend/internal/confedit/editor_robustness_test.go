package confedit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/confwrite"
)

// Every hostile document must be handled well under this bound: the editor is
// reached from an HTTP request and must not let one body pin a CPU.
const robustnessTimeBudget = 2 * time.Second

// buildAliasFanOut builds a "billion laughs" document: each level references
// the previous one ten times, so a naive alias expansion would visit 10^9
// nodes. A password line gives the secret merge something to work on.
func buildAliasFanOut(maskedSecret bool) string {
	var builder strings.Builder
	builder.WriteString("level0: &level0 [lol, lol, lol, lol, lol, lol, lol, lol, lol, lol]\n")
	for levelIndex := 1; levelIndex <= 9; levelIndex++ {
		previousAlias := "*level" + string(rune('0'+levelIndex-1))
		builder.WriteString("level" + string(rune('0'+levelIndex)) + ": &level" + string(rune('0'+levelIndex)) + " [")
		builder.WriteString(strings.TrimSuffix(strings.Repeat(previousAlias+", ", 10), ", "))
		builder.WriteString("]\n")
	}
	if maskedSecret {
		builder.WriteString("password: [REDACTED]\n")
	} else {
		builder.WriteString("password: hunter2\n")
	}
	return builder.String()
}

// buildDeepNesting nests flow sequences far beyond any real configuration;
// the yaml decoder and the merge depth guard must both refuse it cleanly.
func buildDeepNesting(depth int) string {
	return "password: [REDACTED]\nkey: " + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "\n"
}

// buildLargeDocument fills exactly MaxFileBytes with many small mappings.
func buildLargeDocument() string {
	entryLine := "- key_name: some value used to fill the document\n"
	document := "entries:\n" + strings.Repeat(entryLine, (confwrite.MaxFileBytes-len("entries:\n"))/len(entryLine))
	return document
}

func runWithinBudget(testContext *testing.T, caseName string, action func()) {
	testContext.Helper()
	startTime := time.Now()
	action()
	if elapsed := time.Since(startTime); elapsed > robustnessTimeBudget {
		testContext.Errorf("%s took %v, budget %v", caseName, elapsed, robustnessTimeBudget)
	}
}

// Validate and Save over each hostile document: the outcome may be an issue or
// an error, what matters is that it comes back quickly and without panic.
func TestHostileDocumentsFinishQuicklyWithoutPanic(testContext *testing.T) {
	hostileDocuments := map[string]string{
		"large":            buildLargeDocument(),
		"alias fan-out":    buildAliasFanOut(true),
		"deep nesting":     buildDeepNesting(100000),
		"moderate nesting": buildDeepNesting(5000),
	}
	for caseName, submittedContent := range hostileDocuments {
		editor, configDirectory := newTestEditor(testContext, passingConfigTest)
		writeConfigFile(testContext, configDirectory, localOverrideName, buildAliasFanOut(false))
		file := readForEdit(testContext, editor, localOverrideName)
		runWithinBudget(testContext, caseName+" validate", func() {
			editor.Validate(context.Background(), localOverrideName, []byte(submittedContent))
		})
		runWithinBudget(testContext, caseName+" save", func() {
			editor.Save(context.Background(), SaveRequest{Name: localOverrideName, Content: []byte(submittedContent), ExpectedDigest: file.Digest})
		})
	}
}

func TestOversizedContentIsRefusedAsTooLarge(testContext *testing.T) {
	editor, _ := newTestEditor(testContext, passingConfigTest)
	oversizedContent := []byte("a: " + strings.Repeat("x", confwrite.MaxFileBytes) + "\n")

	if _, validateError := editor.Validate(context.Background(), profilesName, oversizedContent); !errors.Is(validateError, confwrite.ErrTooLarge) {
		testContext.Errorf("validate: got %v, want ErrTooLarge", validateError)
	}
	if _, saveError := editor.Save(context.Background(), SaveRequest{Name: profilesName, Content: oversizedContent, ExpectedDigest: AbsentDigest}); !errors.Is(saveError, confwrite.ErrTooLarge) {
		testContext.Errorf("save: got %v, want ErrTooLarge", saveError)
	}
}

// An oversized file already on disk cannot be edited: reading it reports
// ErrTooLarge rather than a truncated text that a save would then persist.
func TestReadOfOversizedFileIsRefused(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, "a: "+strings.Repeat("x", confwrite.MaxFileBytes)+"\n")

	if _, readError := editor.Read(context.Background(), profilesName); !errors.Is(readError, confwrite.ErrTooLarge) {
		testContext.Fatalf("got %v, want ErrTooLarge", readError)
	}
}
