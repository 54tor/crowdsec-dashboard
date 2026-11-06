package confschema

import (
	"slices"
	"testing"
)

// findIssue returns the first issue matching both code and path, so each test
// asserts on the precise problem it targets instead of on the whole slice.
func findIssue(issues []Issue, code string, path string) (Issue, bool) {
	indexFound := slices.IndexFunc(issues, func(issue Issue) bool {
		return issue.Code == code && issue.Path == path
	})
	if indexFound < 0 {
		return Issue{}, false
	}
	return issues[indexFound], true
}

// assertIssue fails unless an issue with the given code/path exists with the
// expected severity and line (line 0 means "do not check the line").
func assertIssue(testContext *testing.T, issues []Issue, code string, path string, severity string, line int) {
	testContext.Helper()
	foundIssue, wasFound := findIssue(issues, code, path)
	if !wasFound {
		testContext.Fatalf("expected %s on %q, got %+v", code, path, issues)
	}
	if foundIssue.Severity != severity {
		testContext.Fatalf("expected severity %s for %s on %q, got %+v", severity, code, path, foundIssue)
	}
	if line != 0 && foundIssue.Line != line {
		testContext.Fatalf("expected line %d for %s on %q, got %+v", line, code, path, foundIssue)
	}
}

func assertNoIssues(testContext *testing.T, issues []Issue) {
	testContext.Helper()
	if len(issues) != 0 {
		testContext.Fatalf("expected no issue, got %+v", issues)
	}
}

// A syntax error must be a blocking error and carry the line reported by the
// YAML parser, so the editor can point at it. Pinned value: for an unclosed
// flow sequence opened on line 3, go.yaml.in/yaml/v3 reports line 2 (it
// reports the construct's opening mark, one line low). The test pins the
// library behaviour so an upgrade that changes it is noticed.
func TestReportsSyntaxErrorWithExactLineNumber(testContext *testing.T) {
	content := []byte("common:\n  log_level: info\napi: [unclosed\nprometheus: {}\n")

	issues := Validate("config.yaml", content)

	if len(issues) != 1 {
		testContext.Fatalf("expected exactly one issue, got %+v", issues)
	}
	expectedIssue := Issue{Line: 2, Path: "", Severity: SeverityError, Code: CodeInvalidYAML}
	if issues[0] != expectedIssue {
		testContext.Fatalf("expected %+v, got %+v", expectedIssue, issues[0])
	}
}

// The line reported for an error in a later document of a multi-document
// stream is absolute (counted from the top of the file), not per document:
// the unclosed sequence opens on line 6 and the parser reports 5 (same
// one-line-low quirk as above), which is not relative to the second document.
func TestReportsSyntaxErrorInSecondDocumentWithAbsoluteLine(testContext *testing.T) {
	content := []byte("name: first\nfilters:\n  - a\n---\nname: second\nfilters: [unclosed\n")

	issues := Validate("profiles.yaml", content)

	assertIssue(testContext, issues, CodeInvalidYAML, "", SeverityError, 5)
}

// A document whose root is a scalar is a container mismatch: always an error.
func TestRejectsScalarRoot(testContext *testing.T) {
	issues := Validate("config.yaml", []byte("just a string\n"))

	assertIssue(testContext, issues, CodeWrongType, "", SeverityError, 1)
}

// Decision: a completely empty config.yaml is accepted silently. CrowdSec
// fills every default itself, and an empty file is a legitimate starting point.
func TestAcceptsEmptyMainConfig(testContext *testing.T) {
	assertNoIssues(testContext, Validate("config.yaml", []byte("")))
	assertNoIssues(testContext, Validate("config.yaml", []byte("# only a comment\n")))
}

func TestAcceptsEmptyOverride(testContext *testing.T) {
	assertNoIssues(testContext, Validate("config.yaml.local", []byte("")))
}

// A string key given a non-string scalar is coercible, so it is only a
// warning and must never block the save. Collections are real errors.
func TestStringKeyWithScalarMismatchIsOnlyAWarning(testContext *testing.T) {
	issues := Validate("config.yaml", []byte("api:\n  server:\n    listen_uri: 12\n"))

	assertIssue(testContext, issues, CodeWrongType, "api.server.listen_uri", SeverityWarning, 3)
}

func TestStringKeyWithCollectionIsAnError(testContext *testing.T) {
	issues := Validate("config.yaml", []byte("api:\n  server:\n    listen_uri: [a, b]\n    log_level:\n      nested: 1\n"))

	assertIssue(testContext, issues, CodeWrongType, "api.server.listen_uri", SeverityError, 3)
	assertIssue(testContext, issues, CodeWrongType, "api.server.log_level", SeverityError, 5)
}

// Booleans accept the YAML 1.1 spellings (yes/no/on/off/y/n), quoted or not,
// because CrowdSec's parser coerces them. A non-boolean string is an error in
// a strict section such as api.server.
func TestBoolKeyAcceptsYamlSpellingsAndRejectsOtherStrings(testContext *testing.T) {
	acceptedContent := []byte("api:\n  server:\n    enable: yes\n    use_forwarded_for_headers: \"on\"\n    disable_remote_lapi_registration: N\n")
	rejectedContent := []byte("api:\n  server:\n    enable: maybe\n")

	assertNoIssues(testContext, Validate("config.yaml.local", acceptedContent))
	assertIssue(testContext, Validate("config.yaml.local", rejectedContent), CodeWrongType, "api.server.enable", SeverityError, 3)
}

// An integer key accepts integral floats silently, warns on a quoted number
// and errors on text or a non-integral number.
func TestIntKeyCoercions(testContext *testing.T) {
	integralFloat := Validate("config.yaml.local", []byte("db_config:\n  port: 5432.0\n"))
	quotedNumber := Validate("config.yaml.local", []byte("db_config:\n  port: \"5432\"\n"))
	text := Validate("config.yaml.local", []byte("db_config:\n  port: abc\n"))
	fraction := Validate("config.yaml.local", []byte("db_config:\n  port: 5.5\n"))

	assertNoIssues(testContext, integralFloat)
	assertIssue(testContext, quotedNumber, CodeWrongType, "db_config.port", SeverityWarning, 2)
	assertIssue(testContext, text, CodeWrongType, "db_config.port", SeverityError, 2)
	assertIssue(testContext, fraction, CodeWrongType, "db_config.port", SeverityError, 2)
}

// Sections beyond the core lot-1 tables (config_paths, crowdsec_service, ...)
// are "soft": a bad scalar there is only a warning, but a collection where a
// scalar belongs is still an error.
func TestSoftSectionsDowngradeScalarMismatches(testContext *testing.T) {
	content := []byte("crowdsec_service:\n  parser_routines: lots\n  enable: maybe\n  acquisition_path: [a]\n")

	issues := Validate("config.yaml.local", content)

	assertIssue(testContext, issues, CodeWrongType, "crowdsec_service.parser_routines", SeverityWarning, 2)
	assertIssue(testContext, issues, CodeWrongType, "crowdsec_service.enable", SeverityWarning, 3)
	assertIssue(testContext, issues, CodeWrongType, "crowdsec_service.acquisition_path", SeverityError, 4)
}

// Unknown keys are warnings everywhere, and a .local override never reports
// missing sections.
func TestWarnsOnUnknownKeysAndNeverRequiresInLocalOverride(testContext *testing.T) {
	content := []byte("mystery_section:\n  a: 1\ncommon:\n  nope: true\n")

	issues := Validate("config.yaml.local", content)

	assertIssue(testContext, issues, CodeUnknownKey, "mystery_section", SeverityWarning, 1)
	assertIssue(testContext, issues, CodeUnknownKey, "common.nope", SeverityWarning, 4)
	for _, requiredKey := range []string{"common", "config_paths", "api"} {
		if _, wasFound := findIssue(issues, CodeMissingRequired, requiredKey); wasFound {
			testContext.Fatalf("%s must not be required in config.yaml.local: %+v", requiredKey, issues)
		}
	}
}

// Missing core sections in config.yaml are only warnings: CrowdSec has
// defaults for them, so a save must never be blocked.
func TestMainConfigMissingSectionsAreWarnings(testContext *testing.T) {
	issues := Validate("config.yaml", []byte("prometheus:\n  enabled: true\n"))

	for _, requiredKey := range []string{"common", "config_paths", "api"} {
		assertIssue(testContext, issues, CodeMissingRequired, requiredKey, SeverityWarning, 0)
	}
}

// Profiles: each YAML document is validated independently; name/filters are
// documented but a missing one is only a warning. A scalar filters is a
// container mismatch and therefore an error.
func TestValidatesEachProfileDocument(testContext *testing.T) {
	content := []byte("name: ip_remediation\nfilters:\n  - Alert.Remediation == true\ndecisions:\n  - type: ban\n    duration: 4h\non_success: break\n---\nfilters: not_a_list\ndecisions: []\n")

	issues := Validate("profiles.yaml", content)

	assertIssue(testContext, issues, CodeMissingRequired, "name", SeverityWarning, 0)
	assertIssue(testContext, issues, CodeWrongType, "filters", SeverityError, 9)
	if len(issues) != 2 {
		testContext.Fatalf("the first document is valid, got %+v", issues)
	}
}

// Acquisition without "source" is the one hard missing-key error. The file
// lives in a real acquis.d directory and uses the .yml extension.
func TestAcquisitionRequiresSourceKey(testContext *testing.T) {
	content := []byte("source: docker\ncontainer_name_regexp:\n  - .*nginx.*\nlabels:\n  type: nginx\n---\nfilenames:\n  - /var/log/a.log\nlabels:\n  type: syslog\n")

	issues := Validate("/etc/crowdsec/acquis.d/web.yml", content)

	assertIssue(testContext, issues, CodeMissingRequired, "source", SeverityError, 7)
	if len(issues) != 1 {
		testContext.Fatalf("docker keys are known, got %+v", issues)
	}
}

// Sources added in the second round must not raise unknown_key.
func TestAcquisitionKnowsAllDocumentedSources(testContext *testing.T) {
	content := []byte(`source: loki
url: http://loki:3100
query: '{job="a"}'
limit: 100
labels:
  type: x
---
source: http
listen_addr: 127.0.0.1:8081
auth_type: headers
headers:
  A: b
tls:
  server_cert: c
  server_key: k
labels:
  type: x
---
source: s3
polling_method: list
bucket_name: b
labels:
  type: x
---
source: kinesis
stream_name: s
labels:
  type: x
---
source: wineventlog
event_channel: Security
event_ids: [4625]
labels:
  type: x
---
source: file
filenames: [/var/log/a.log]
max_buffer_size: 100
unique_id: abc
---
source: kafka
brokers: [a:9092]
topic: t
partition: 0
---
source: syslog
listen_port: 514
tls: {}
`)

	assertNoIssues(testContext, Validate("acquis.yaml", content))
}

// Whitelists are only validated when the file declares a "whitelist" key.
func TestValidatesWhitelistFiles(testContext *testing.T) {
	validContent := []byte("name: my/whitelist\ndescription: mine\nwhitelist:\n  reason: lan\n  cidr:\n    - 10.0.0.0/8\n")
	incompleteContent := []byte("whitelist:\n  ip: [1.2.3.4]\n")

	assertNoIssues(testContext, Validate("parsers/s02-enrich/my-whitelist.yaml", validContent))
	incompleteIssues := Validate("postoverflows/s01-whitelist/x.yaml", incompleteContent)
	for _, missingPath := range []string{"name", "description", "whitelist.reason"} {
		assertIssue(testContext, incompleteIssues, CodeMissingRequired, missingPath, SeverityWarning, 0)
	}
}

// A regular grok parser lives in the same directories but has no whitelist
// key: it must not be flagged at all.
func TestNormalParserFileGetsNoSchemaIssue(testContext *testing.T) {
	content := []byte("filter: \"evt.Line.Labels.type == 'nginx'\"\nonsuccess: next_stage\nname: crowdsecurity/nginx-logs\ngrok:\n  pattern: '%{IP:remote}'\n  apply_on: message\nstatics:\n  - meta: service\n    value: http\n")

	assertNoIssues(testContext, Validate("/etc/crowdsec/parsers/s01-parse/nginx-logs.yaml", content))
}

// Directory matching is by path segment: "myparsers" and "foo-acquis.d" are
// not CrowdSec directories, so only the syntax is checked there.
func TestDirectoryMatchingUsesPathSegments(testContext *testing.T) {
	notSource := []byte("foo: bar\n")

	assertNoIssues(testContext, Validate("myparsers/x.yaml", []byte("whitelist:\n  ip: []\n")))
	assertNoIssues(testContext, Validate("foo-acquis.d/x.yaml", notSource))
	assertIssue(testContext, Validate("myparsers/x.yaml", []byte("a: [oops\n")), CodeInvalidYAML, "", SeverityError, 1)
}

// Anchors, aliases and merge keys are legal YAML. Required keys supplied via
// "<<" cannot be seen locally, so required checks are skipped for a mapping
// that merges, and aliased values are validated through the alias.
func TestSupportsAnchorsAliasesAndMergeKeys(testContext *testing.T) {
	profileContent := []byte("name: p1\nfilters: &shared\n  - a\n---\n<<: {name: p2}\nfilters: *shared\n---\n<<: {name: p3, filters: [b]}\n")
	aliasedWrongType := []byte("api:\n  server:\n    enable: &flag maybe\n    use_forwarded_for_headers: *flag\n")

	assertNoIssues(testContext, Validate("profiles.yaml", profileContent))
	issues := Validate("config.yaml.local", aliasedWrongType)
	assertIssue(testContext, issues, CodeWrongType, "api.server.use_forwarded_for_headers", SeverityError, 0)
}

// Explicit and implicit nulls mean "unset": they never raise a type error,
// whatever the expected kind.
func TestNullValuesAreAccepted(testContext *testing.T) {
	content := []byte("api:\n  server:\n    enable: ~\n    listen_uri:\n    trusted_ips: null\ncommon:\n")

	assertNoIssues(testContext, Validate("config.yaml.local", content))
}

// A root that is a sequence for a mapping family is a container mismatch.
func TestRejectsSequenceRootForProfiles(testContext *testing.T) {
	issues := Validate("profiles.yaml", []byte("- name: a\n"))

	assertIssue(testContext, issues, CodeWrongType, "", SeverityError, 1)
}
