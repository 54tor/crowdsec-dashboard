package cscli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingRunner struct {
	receivedArgv []string
	calls        int
	stdout       []byte
	err          error
}

func (runner *recordingRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.calls++
	runner.receivedArgv = argv
	return runner.stdout, runner.err
}

func TestUnknownCommandIsRejected(t *testing.T) {
	runner := &recordingRunner{}

	_, err := execute(context.Background(), runner, "bash", map[string]string{"name": "x"})

	if !errors.Is(err, ErrUnknownCommand) {
		t.Fatalf("expected ErrUnknownCommand, got %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("runner must not be called, was called %d times", runner.calls)
	}
}

func TestAppSecHubCommandsBuildFixedArgv(testContext *testing.T) {
	testCases := []struct {
		commandName  string
		expectedArgv []string
	}{
		{"appsec_rules_install", []string{"cscli", "appsec-rules", "install", "crowdsecurity/vpatch-env-access"}},
		{"appsec_rules_remove", []string{"cscli", "appsec-rules", "remove", "crowdsecurity/vpatch-env-access"}},
		{"appsec_configs_install", []string{"cscli", "appsec-configs", "install", "crowdsecurity/vpatch-env-access"}},
		{"appsec_configs_remove", []string{"cscli", "appsec-configs", "remove", "crowdsecurity/vpatch-env-access"}},
	}
	for _, testCase := range testCases {
		runner := &recordingRunner{}

		_, executeError := execute(context.Background(), runner, testCase.commandName, map[string]string{"name": "crowdsecurity/vpatch-env-access"})

		if executeError != nil || !reflect.DeepEqual(runner.receivedArgv, testCase.expectedArgv) {
			testContext.Errorf("%s: expected %v, got %v (%v)", testCase.commandName, testCase.expectedArgv, runner.receivedArgv, executeError)
		}
		_, refusedError := execute(context.Background(), &recordingRunner{}, testCase.commandName, map[string]string{"name": "--force"})
		if refusedError == nil {
			testContext.Errorf("%s: a flag-like name must be refused", testCase.commandName)
		}
	}
}

func TestExecuteBuildsExpectedArgv(t *testing.T) {
	testCases := []struct {
		name         string
		fields       map[string]string
		expectedArgv []string
	}{
		{"alerts_delete", map[string]string{"id": "42"}, []string{"cscli", "alerts", "delete", "--id", "42"}},
		{"bouncers_list", nil, []string{"cscli", "bouncers", "list", "-o", "json"}},
		{"bouncers_add", map[string]string{"name": "fw-1"}, []string{"cscli", "bouncers", "add", "fw-1"}},
		{"bouncers_delete", map[string]string{"name": "fw-1"}, []string{"cscli", "bouncers", "delete", "fw-1"}},
		{"machines_list", nil, []string{"cscli", "machines", "list", "-o", "json"}},
		{"machines_add", map[string]string{"name": "m1"}, []string{"cscli", "machines", "add", "m1", "--auto", "-f", "/dev/stdout"}},
		{"machines_validate", map[string]string{"name": "m1"}, []string{"cscli", "machines", "validate", "m1"}},
		{"machines_delete", map[string]string{"name": "m1"}, []string{"cscli", "machines", "delete", "m1"}},
		{"hub_list", nil, []string{"cscli", "hub", "list", "-o", "json"}},
		{"hub_update", nil, []string{"cscli", "hub", "update"}},
		{"hub_upgrade", nil, []string{"cscli", "hub", "upgrade"}},
		{"collections_remove", map[string]string{"name": "crowdsecurity/linux"}, []string{"cscli", "collections", "remove", "crowdsecurity/linux"}},
		{"metrics", nil, []string{"cscli", "metrics", "-o", "json"}},
		{"version", nil, []string{"cscli", "version"}},
		{"reload", nil, []string{"kill", "-HUP", "1"}},
		{"config_test", nil, []string{"crowdsec", "-t"}},
	}
	for _, testCase := range testCases {
		runner := &recordingRunner{}

		_, err := execute(context.Background(), runner, testCase.name, testCase.fields)

		if err != nil {
			t.Fatalf("%s: unexpected error %v", testCase.name, err)
		}
		if !reflect.DeepEqual(runner.receivedArgv, testCase.expectedArgv) {
			t.Fatalf("%s: expected %v, got %v", testCase.name, testCase.expectedArgv, runner.receivedArgv)
		}
	}
}

func TestBanTargetRejectsInvalidInputs(t *testing.T) {
	testCases := []struct {
		label string
		value string
	}{
		{"ipv4 prefix too long", "1.2.3.4/33"},
		{"ipv6 prefix too long", "2001:db8::/129"},
		{"empty", ""},
		{"shell injection", "1.2.3.4; rm -rf /"},
		{"too long", strings.Repeat("a", 300)},
		{"leading dash", "--all"},
		{"range", "1.2.3.4-1.2.3.9"},
		{"space", "1.2.3.4 "},
		{"zone interface", "fe80::1%eth0"},
		{"zone long", "fe80::1%" + strings.Repeat("a", 300)},
		{"zone with space", "fe80::1%a b"},
		{"zone newline", "fe80::1%\n-x"},
		{"ipv4 mapped", "::ffff:1.2.3.4"},
		{"long digits", strings.Repeat("1", 300)},
		{"long letters", strings.Repeat("a", 300)},
	}
	for _, testCase := range testCases {
		if err := ValidateTarget(testCase.value); !errors.Is(err, ErrInvalidField) {
			t.Fatalf("%s: expected ErrInvalidField, got %v", testCase.label, err)
		}
	}
}

func TestAlertsDeleteRejectsIPField(t *testing.T) {
	runner := &recordingRunner{}

	_, err := execute(context.Background(), runner, "alerts_delete", map[string]string{"ip": "1.2.3.4"})

	if !errors.Is(err, ErrInvalidField) {
		t.Fatalf("expected ErrInvalidField, got %v", err)
	}
	if runner.calls != 0 {
		t.Fatal("runner must not be called")
	}
}

func TestCollectionNameRejectsLeadingDash(t *testing.T) {
	runner := &recordingRunner{}

	_, err := execute(context.Background(), runner, "collections_install", map[string]string{"name": "--force"})

	if !errors.Is(err, ErrInvalidField) {
		t.Fatalf("expected ErrInvalidField, got %v", err)
	}
	if runner.calls != 0 {
		t.Fatal("runner must not be called")
	}
}

func TestCollectionNameAcceptsHubIdentifier(t *testing.T) {
	runner := &recordingRunner{}

	_, err := execute(context.Background(), runner, "collections_install", map[string]string{"name": "crowdsecurity/linux"})

	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	expectedArgv := []string{"cscli", "collections", "install", "crowdsecurity/linux"}
	if !reflect.DeepEqual(runner.receivedArgv, expectedArgv) {
		t.Fatalf("expected %v, got %v", expectedArgv, runner.receivedArgv)
	}
}

func TestInvalidNamesAndIdsAreRejected(t *testing.T) {
	testCases := []struct {
		command string
		field   string
		value   string
	}{
		{"bouncers_add", "name", "-x"},
		{"bouncers_add", "name", "a b"},
		{"bouncers_add", "name", strings.Repeat("a", 65)},
		{"bouncers_delete", "name", "--x@y"},
		{"bouncers_delete", "name", "@x"},
		{"bouncers_delete", "name", "fe80::1"},
		{"machines_delete", "name", "m@203.0.113.7"},
		{"machines_delete", "name", ""},
		{"alerts_delete", "id", "12345678901"},
		{"alerts_delete", "id", "-1"},
		{"alerts_delete", "id", "1;2"},
	}
	for _, testCase := range testCases {
		_, err := execute(context.Background(), &recordingRunner{}, testCase.command, map[string]string{testCase.field: testCase.value})

		if !errors.Is(err, ErrInvalidField) {
			t.Fatalf("%s %q: expected ErrInvalidField, got %v", testCase.command, testCase.value, err)
		}
	}
}

func TestMissingAndExtraFieldsAreRejected(t *testing.T) {
	testCases := []struct {
		command string
		fields  map[string]string
	}{
		{"bouncers_add", nil},
		{"bouncers_add", map[string]string{"name": "ok", "extra": "x"}},
		{"bouncers_list", map[string]string{"name": "ok"}},
		{"reload", map[string]string{"name": "ok"}},
		{"alerts_delete", map[string]string{}},
		{"alerts_delete", map[string]string{"id": "1", "ip": "1.2.3.4"}},
	}
	for _, testCase := range testCases {
		runner := &recordingRunner{}

		_, err := execute(context.Background(), runner, testCase.command, testCase.fields)

		if !errors.Is(err, ErrInvalidField) {
			t.Fatalf("%s %v: expected ErrInvalidField, got %v", testCase.command, testCase.fields, err)
		}
		if runner.calls != 0 {
			t.Fatalf("%s: runner must not be called", testCase.command)
		}
	}
}

func TestDurationValidation(t *testing.T) {
	validDurations := []string{"4h", "30m", "1d", "9999s"}
	invalidDurations := []string{"", "4", "h", "-4h", "10000h", "4h;", "4 h", "4w"}
	for _, duration := range validDurations {
		if err := validateDuration(duration); err != nil {
			t.Fatalf("%q should be valid: %v", duration, err)
		}
	}
	for _, duration := range invalidDurations {
		if err := validateDuration(duration); !errors.Is(err, ErrInvalidField) {
			t.Fatalf("%q should be invalid, got %v", duration, err)
		}
	}
}

func TestDecodeListTreatsNullAsEmpty(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}
	for _, raw := range []string{"", "  ", "null", "[]", "null\n"} {
		decoded, err := DecodeList[item]([]byte(raw))

		if err != nil {
			t.Fatalf("%q: unexpected error %v", raw, err)
		}
		if decoded == nil || len(decoded) != 0 {
			t.Fatalf("%q: expected empty non-nil slice, got %#v", raw, decoded)
		}
	}
}

func TestDecodeListDecodesItems(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}

	decoded, err := DecodeList[item]([]byte(`[{"name":"a"},{"name":"b"}]`))

	if err != nil || len(decoded) != 2 || decoded[1].Name != "b" {
		t.Fatalf("unexpected result %#v, %v", decoded, err)
	}
	if _, err := DecodeList[item]([]byte(`{not json`)); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestBouncerNameAcceptsAtSignAfterFirstCharacter(t *testing.T) {
	runner := &recordingRunner{}

	_, err := execute(context.Background(), runner, "bouncers_delete", map[string]string{"name": "cs-fw@203.0.113.7"})

	if err != nil || !reflect.DeepEqual(runner.receivedArgv, []string{"cscli", "bouncers", "delete", "cs-fw@203.0.113.7"}) {
		t.Fatalf("unexpected result: %v %v", err, runner.receivedArgv)
	}
}

func TestConfigTestRunsCrowdsecValidationAndFailsClosed(t *testing.T) {
	passingRunner := &recordingRunner{}
	if testError := ConfigTest(context.Background(), NewLocalExecutor(passingRunner)); testError != nil {
		t.Fatalf("unexpected error %v", testError)
	}
	if !reflect.DeepEqual(passingRunner.receivedArgv, []string{"crowdsec", "-t"}) {
		t.Fatalf("config test argv must be exactly crowdsec -t, got %v", passingRunner.receivedArgv)
	}
	// Exit status 1 (invalid configuration) and a missing binary both surface as errors.
	failingRunner := &recordingRunner{err: ErrCscliFailed}
	if testError := ConfigTest(context.Background(), NewLocalExecutor(failingRunner)); testError == nil {
		t.Fatal("a failing crowdsec -t must return an error")
	}
}
