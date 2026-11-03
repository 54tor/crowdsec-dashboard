package cscli

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func executeAllowlistCommand(testContext *testing.T, commandName string, fields map[string]string) ([]string, error) {
	testContext.Helper()
	runner := &recordingRunner{}
	_, executionError := Execute(context.Background(), runner, commandName, fields)
	return runner.receivedArgv, executionError
}

func assertRefused(testContext *testing.T, label string, argv []string, executionError error) {
	testContext.Helper()
	if !errors.Is(executionError, ErrInvalidField) {
		testContext.Fatalf("%s must be refused, got %v", label, executionError)
	}
	if len(argv) != 0 {
		testContext.Fatalf("%s: runner must never be invoked, got argv %v", label, argv)
	}
}

func TestAllowlistsCreateBuildsFixedArgv(testContext *testing.T) {
	argvObtenu, executionError := executeAllowlistCommand(testContext, "allowlists_create",
		map[string]string{"name": "office", "description": "Office network"})

	if executionError != nil {
		testContext.Fatalf("unexpected error %v", executionError)
	}
	argvAttendu := []string{"cscli", "allowlists", "create", "office", "--description=Office network"}
	if !reflect.DeepEqual(argvObtenu, argvAttendu) {
		testContext.Fatalf("expected %v, got %v", argvAttendu, argvObtenu)
	}
}

func TestAllowlistsDeleteAndRemoveBuildFixedArgv(testContext *testing.T) {
	argvSuppression, deleteError := executeAllowlistCommand(testContext, "allowlists_delete", map[string]string{"name": "office"})
	argvRetrait, removeError := executeAllowlistCommand(testContext, "allowlists_remove",
		map[string]string{"name": "office", "value": "192.0.2.0/24"})

	if deleteError != nil || removeError != nil {
		testContext.Fatalf("unexpected errors %v / %v", deleteError, removeError)
	}
	if !reflect.DeepEqual(argvSuppression, []string{"cscli", "allowlists", "delete", "office"}) {
		testContext.Fatalf("unexpected delete argv %v", argvSuppression)
	}
	if !reflect.DeepEqual(argvRetrait, []string{"cscli", "allowlists", "remove", "office", "192.0.2.0/24"}) {
		testContext.Fatalf("unexpected remove argv %v", argvRetrait)
	}
}

func TestAllowlistsAddWithAllFieldsBuildsFlags(testContext *testing.T) {
	argvObtenu, executionError := executeAllowlistCommand(testContext, "allowlists_add", map[string]string{
		"name": "office", "value": "2001:db8::1", "expiration": "12h", "comment": "vpn",
	})

	if executionError != nil {
		testContext.Fatalf("unexpected error %v", executionError)
	}
	argvAttendu := []string{"cscli", "allowlists", "add", "office", "2001:db8::1", "--expiration=12h", "--comment=vpn"}
	if !reflect.DeepEqual(argvObtenu, argvAttendu) {
		testContext.Fatalf("expected %v, got %v", argvAttendu, argvObtenu)
	}
}

func TestAllowlistsAddWithoutOptionalFieldsOmitsFlags(testContext *testing.T) {
	argvObtenu, executionError := executeAllowlistCommand(testContext, "allowlists_add",
		map[string]string{"name": "office", "value": "192.0.2.7"})

	if executionError != nil {
		testContext.Fatalf("unexpected error %v", executionError)
	}
	argvAttendu := []string{"cscli", "allowlists", "add", "office", "192.0.2.7"}
	if !reflect.DeepEqual(argvObtenu, argvAttendu) {
		testContext.Fatalf("expected %v, got %v", argvAttendu, argvObtenu)
	}
}

func TestAllowlistsAddPassesCommentAsSingleFlagValue(testContext *testing.T) {
	argvObtenu, executionError := executeAllowlistCommand(testContext, "allowlists_add", map[string]string{
		"name": "office", "value": "192.0.2.7", "comment": "a b --force",
	})

	if executionError != nil {
		testContext.Fatalf("unexpected error %v", executionError)
	}
	if !slices.Contains(argvObtenu, "--comment=a b --force") || len(argvObtenu) != 6 {
		testContext.Fatalf("comment must be one argv element, got %v", argvObtenu)
	}
}

func TestAllowlistsRejectsControlFormatAndSeparatorCharacters(testContext *testing.T) {
	forbiddenTexts := []string{
		"line\nbreak", "nul\x00byte", "bidi\u202eoverride", "line\u2028separator",
		"paragraph\u2029separator", "zero\u200bwidth", "bom\ufeffmark", "-e 0s", "",
		strings.Repeat("a", 257), "bad\xffutf8",
	}
	for _, forbiddenText := range forbiddenTexts {
		descriptionArgv, descriptionError := executeAllowlistCommand(testContext, "allowlists_create",
			map[string]string{"name": "office", "description": forbiddenText})
		commentArgv, commentError := executeAllowlistCommand(testContext, "allowlists_add",
			map[string]string{"name": "office", "value": "192.0.2.7", "comment": forbiddenText})

		assertRefused(testContext, "description "+forbiddenText, descriptionArgv, descriptionError)
		assertRefused(testContext, "comment "+forbiddenText, commentArgv, commentError)
	}
}

func TestAllowlistNameLongerThan32Refused(testContext *testing.T) {
	_, acceptedError := executeAllowlistCommand(testContext, "allowlists_delete", map[string]string{"name": strings.Repeat("a", 32)})
	refusedArgv, refusedError := executeAllowlistCommand(testContext, "allowlists_delete", map[string]string{"name": strings.Repeat("a", 33)})

	if acceptedError != nil {
		testContext.Fatalf("32 characters must be accepted, got %v", acceptedError)
	}
	assertRefused(testContext, "33 characters", refusedArgv, refusedError)
}

func TestAllowlistsRefuseInvalidNameCharset(testContext *testing.T) {
	invalidNames := []string{
		"../x", "-e", "-x", "Office", "a b", "a\nb", "a\x00b", "a\u202eb", "a\u200bb", "", strings.Repeat("a", 33),
	}
	commandFields := map[string]map[string]string{
		"allowlists_create": {"description": "d"},
		"allowlists_delete": {},
		"allowlists_add":    {"value": "192.0.2.7"},
		"allowlists_remove": {"value": "192.0.2.7"},
	}
	for commandName, otherFields := range commandFields {
		for _, invalidName := range invalidNames {
			fields := map[string]string{"name": invalidName}
			for otherName, otherValue := range otherFields {
				fields[otherName] = otherValue
			}

			argv, executionError := executeAllowlistCommand(testContext, commandName, fields)

			assertRefused(testContext, commandName+" name "+invalidName, argv, executionError)
		}
	}
}

func TestAllowlistsRefuseInjectionInValue(testContext *testing.T) {
	for _, injectedValue := range []string{"-1.2.3.4", "192.0.2.7\n", "a b"} {
		addArgv, addError := executeAllowlistCommand(testContext, "allowlists_add",
			map[string]string{"name": "office", "value": injectedValue})
		removeArgv, removeError := executeAllowlistCommand(testContext, "allowlists_remove",
			map[string]string{"name": "office", "value": injectedValue})

		assertRefused(testContext, "add value "+injectedValue, addArgv, addError)
		assertRefused(testContext, "remove value "+injectedValue, removeArgv, removeError)
	}
}

func TestAllowlistsAcceptCanonicalValuesAndExpirations(testContext *testing.T) {
	for _, canonicalValue := range []string{"192.0.2.7", "192.0.2.7/32", "192.0.2.0/24", "2001:db8::/32"} {
		_, executionError := executeAllowlistCommand(testContext, "allowlists_add",
			map[string]string{"name": "office", "value": canonicalValue})
		if executionError != nil {
			testContext.Fatalf("value %q must be accepted, got %v", canonicalValue, executionError)
		}
	}
	for _, validExpiration := range []string{"1d", "9999h", "12h", "7d"} {
		_, executionError := executeAllowlistCommand(testContext, "allowlists_add", map[string]string{
			"name": "office", "value": "192.0.2.7", "expiration": validExpiration,
		})
		if executionError != nil {
			testContext.Fatalf("expiration %q must be accepted, got %v", validExpiration, executionError)
		}
	}
}

func TestAllowlistsRejectsNonCanonicalValue(testContext *testing.T) {
	nonCanonicalValues := []string{"192.0.2.7/24", "::ffff:192.0.2.1", "fe80::1%eth0", "2001:DB8::1", "not-an-ip", ""}
	for _, nonCanonicalValue := range nonCanonicalValues {
		addArgv, addError := executeAllowlistCommand(testContext, "allowlists_add",
			map[string]string{"name": "office", "value": nonCanonicalValue})
		removeArgv, removeError := executeAllowlistCommand(testContext, "allowlists_remove",
			map[string]string{"name": "office", "value": nonCanonicalValue})

		assertRefused(testContext, "add "+nonCanonicalValue, addArgv, addError)
		assertRefused(testContext, "remove "+nonCanonicalValue, removeArgv, removeError)
	}
}

func TestAllowlistsRejectsBadExpiration(testContext *testing.T) {
	for _, badExpiration := range []string{"0.5d", "7w", "99999d", "5m", "", "-1d", "0d", "0h", "00h"} {
		argv, executionError := executeAllowlistCommand(testContext, "allowlists_add", map[string]string{
			"name": "office", "value": "192.0.2.7", "expiration": badExpiration,
		})

		assertRefused(testContext, "expiration "+badExpiration, argv, executionError)
	}
}

func TestAllowlistsRejectUnknownFields(testContext *testing.T) {
	argv, executionError := executeAllowlistCommand(testContext, "allowlists_remove",
		map[string]string{"name": "office", "value": "192.0.2.7", "comment": "x"})

	assertRefused(testContext, "unknown field", argv, executionError)
}

func TestAllowlistsNamesAreListed(testContext *testing.T) {
	listedNames := Names()

	for _, expectedName := range []string{"allowlists_create", "allowlists_delete", "allowlists_add", "allowlists_remove"} {
		if !slices.Contains(listedNames, expectedName) {
			testContext.Fatalf("%s missing from Names()", expectedName)
		}
	}
}
