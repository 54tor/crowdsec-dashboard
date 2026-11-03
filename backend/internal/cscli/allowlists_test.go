package cscli

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func executeAllowlistCommand(t *testing.T, commandName string, fields map[string]string) ([]string, error) {
	t.Helper()
	runner := &recordingRunner{}
	_, executionError := Execute(context.Background(), runner, commandName, fields)
	return runner.receivedArgv, executionError
}

func TestAllowlistsCreateBuildsFixedArgv(t *testing.T) {
	argvObtenu, executionError := executeAllowlistCommand(t, "allowlists_create",
		map[string]string{"name": "office", "description": "Office network"})

	if executionError != nil {
		t.Fatalf("unexpected error %v", executionError)
	}
	argvAttendu := []string{"cscli", "allowlists", "create", "office", "--description=Office network"}
	if !reflect.DeepEqual(argvObtenu, argvAttendu) {
		t.Fatalf("expected %v, got %v", argvAttendu, argvObtenu)
	}
}

func TestAllowlistsDeleteAndRemoveBuildFixedArgv(t *testing.T) {
	argvSuppression, deleteError := executeAllowlistCommand(t, "allowlists_delete", map[string]string{"name": "office"})
	argvRetrait, removeError := executeAllowlistCommand(t, "allowlists_remove",
		map[string]string{"name": "office", "value": "192.0.2.0/24"})

	if deleteError != nil || removeError != nil {
		t.Fatalf("unexpected errors %v / %v", deleteError, removeError)
	}
	if !reflect.DeepEqual(argvSuppression, []string{"cscli", "allowlists", "delete", "office"}) {
		t.Fatalf("unexpected delete argv %v", argvSuppression)
	}
	if !reflect.DeepEqual(argvRetrait, []string{"cscli", "allowlists", "remove", "office", "192.0.2.0/24"}) {
		t.Fatalf("unexpected remove argv %v", argvRetrait)
	}
}

func TestAllowlistsAddWithAllFieldsBuildsFlags(t *testing.T) {
	argvObtenu, executionError := executeAllowlistCommand(t, "allowlists_add", map[string]string{
		"name": "office", "value": "2001:db8::1", "expiration": "12h", "comment": "vpn",
	})

	if executionError != nil {
		t.Fatalf("unexpected error %v", executionError)
	}
	argvAttendu := []string{"cscli", "allowlists", "add", "office", "2001:db8::1", "--expiration=12h", "--comment=vpn"}
	if !reflect.DeepEqual(argvObtenu, argvAttendu) {
		t.Fatalf("expected %v, got %v", argvAttendu, argvObtenu)
	}
}

func TestAllowlistsAddWithoutOptionalFieldsOmitsFlags(t *testing.T) {
	argvObtenu, executionError := executeAllowlistCommand(t, "allowlists_add",
		map[string]string{"name": "office", "value": "192.0.2.7"})

	if executionError != nil {
		t.Fatalf("unexpected error %v", executionError)
	}
	argvAttendu := []string{"cscli", "allowlists", "add", "office", "192.0.2.7"}
	if !reflect.DeepEqual(argvObtenu, argvAttendu) {
		t.Fatalf("expected %v, got %v", argvAttendu, argvObtenu)
	}
}

func TestAllowlistsAddPassesCommentAsSingleFlagValue(t *testing.T) {
	argvObtenu, executionError := executeAllowlistCommand(t, "allowlists_add", map[string]string{
		"name": "office", "value": "192.0.2.7", "comment": "a b --force",
	})

	if executionError != nil {
		t.Fatalf("unexpected error %v", executionError)
	}
	if !slices.Contains(argvObtenu, "--comment=a b --force") || len(argvObtenu) != 6 {
		t.Fatalf("comment must be one argv element, got %v", argvObtenu)
	}
}

func TestAllowlistsRejectsControlFormatAndSeparatorCharacters(t *testing.T) {
	forbiddenTexts := []string{
		"line\nbreak", "nul\x00byte", "bidi\u202eoverride", "line\u2028separator",
		"paragraph\u2029separator", "zero\u200bwidth", "bom\ufeffmark", "-e 0s", "",
		strings.Repeat("a", 257), "bad\xffutf8",
	}
	for _, forbiddenText := range forbiddenTexts {
		_, descriptionError := executeAllowlistCommand(t, "allowlists_create",
			map[string]string{"name": "office", "description": forbiddenText})
		_, commentError := executeAllowlistCommand(t, "allowlists_add",
			map[string]string{"name": "office", "value": "192.0.2.7", "comment": forbiddenText})

		if !errors.Is(descriptionError, ErrInvalidField) || !errors.Is(commentError, ErrInvalidField) {
			t.Fatalf("%q must be refused, got %v / %v", forbiddenText, descriptionError, commentError)
		}
	}
}

func TestAllowlistNameLongerThan32Refused(t *testing.T) {
	_, acceptedError := executeAllowlistCommand(t, "allowlists_delete", map[string]string{"name": strings.Repeat("a", 32)})
	_, refusedError := executeAllowlistCommand(t, "allowlists_delete", map[string]string{"name": strings.Repeat("a", 33)})

	if acceptedError != nil {
		t.Fatalf("32 characters must be accepted, got %v", acceptedError)
	}
	if !errors.Is(refusedError, ErrInvalidField) {
		t.Fatalf("33 characters must be refused, got %v", refusedError)
	}
}

func TestAllowlistsRejectsNonCanonicalValue(t *testing.T) {
	nonCanonicalValues := []string{"192.0.2.7/24", "::ffff:192.0.2.1", "fe80::1%eth0", "2001:DB8::1", "not-an-ip", ""}
	for _, nonCanonicalValue := range nonCanonicalValues {
		_, addError := executeAllowlistCommand(t, "allowlists_add",
			map[string]string{"name": "office", "value": nonCanonicalValue})
		_, removeError := executeAllowlistCommand(t, "allowlists_remove",
			map[string]string{"name": "office", "value": nonCanonicalValue})

		if !errors.Is(addError, ErrInvalidField) || !errors.Is(removeError, ErrInvalidField) {
			t.Fatalf("%q must be refused, got %v / %v", nonCanonicalValue, addError, removeError)
		}
	}
}

func TestAllowlistsRejectsBadExpiration(t *testing.T) {
	for _, badExpiration := range []string{"0.5d", "7w", "99999d", "5m", "", "-1d"} {
		_, executionError := executeAllowlistCommand(t, "allowlists_add", map[string]string{
			"name": "office", "value": "192.0.2.7", "expiration": badExpiration,
		})

		if !errors.Is(executionError, ErrInvalidField) {
			t.Fatalf("%q must be refused, got %v", badExpiration, executionError)
		}
	}
}

func TestAllowlistsRejectUnknownFields(t *testing.T) {
	_, executionError := executeAllowlistCommand(t, "allowlists_remove",
		map[string]string{"name": "office", "value": "192.0.2.7", "comment": "x"})

	if !errors.Is(executionError, ErrInvalidField) {
		t.Fatalf("unknown field must be refused, got %v", executionError)
	}
}

func TestAllowlistsNamesAreListed(t *testing.T) {
	listedNames := Names()

	for _, expectedName := range []string{"allowlists_create", "allowlists_delete", "allowlists_add", "allowlists_remove"} {
		if !slices.Contains(listedNames, expectedName) {
			t.Fatalf("%s missing from Names()", expectedName)
		}
	}
}
