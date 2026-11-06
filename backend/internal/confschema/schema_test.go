package confschema

import (
	"slices"
	"testing"
)

func findIssue(issues []Issue, code string, path string) (Issue, bool) {
	indexFound := slices.IndexFunc(issues, func(issue Issue) bool {
		return issue.Code == code && issue.Path == path
	})
	if indexFound < 0 {
		return Issue{}, false
	}
	return issues[indexFound], true
}

func TestReportsSyntaxErrorWithLineNumber(testContext *testing.T) {
	content := []byte("common:\n  log_level: info\n api: [unclosed\n")

	issues := Validate("config.yaml", content)

	foundIssue, wasFound := findIssue(issues, CodeInvalidYAML, "")
	if !wasFound || foundIssue.Severity != SeverityError || foundIssue.Line == 0 {
		testContext.Fatalf("valeurObtenue=%+v, attendu invalid_yaml avec numero de ligne", issues)
	}
}

func TestReportsWrongTypeForKnownKey(testContext *testing.T) {
	content := []byte("api:\n  server:\n    listen_uri: 12\n    enable: \"yes\"\n")

	issues := Validate("config.yaml", content)

	if _, wasFound := findIssue(issues, CodeWrongType, "api.server.enable"); !wasFound {
		testContext.Fatalf("api.server.enable devrait etre wrong_type: %+v", issues)
	}
	if _, wasFound := findIssue(issues, CodeWrongType, "api.server.listen_uri"); !wasFound {
		testContext.Fatalf("listen_uri: 12 devrait etre wrong_type: %+v", issues)
	}
	mappingContent := []byte("api:\n  server:\n    listen_uri: [a]\n")
	mappingIssues := Validate("config.yaml", mappingContent)
	foundIssue, wasFound := findIssue(mappingIssues, CodeWrongType, "api.server.listen_uri")
	if !wasFound || foundIssue.Line != 3 {
		testContext.Fatalf("sequence a la place d'une chaine: %+v", mappingIssues)
	}
}

func TestWarnsOnUnknownTopLevelKey(testContext *testing.T) {
	content := []byte("mystery_section:\n  a: 1\ncommon:\n  nope: true\n")

	issues := Validate("config.yaml.local", content)

	topLevelIssue, wasFound := findIssue(issues, CodeUnknownKey, "mystery_section")
	if !wasFound || topLevelIssue.Severity != SeverityWarning || topLevelIssue.Line != 1 {
		testContext.Fatalf("unknown_key attendu en warning: %+v", issues)
	}
	if _, wasFound := findIssue(issues, CodeUnknownKey, "common.nope"); !wasFound {
		testContext.Fatalf("common.nope devrait etre unknown_key: %+v", issues)
	}
	if _, wasFound := findIssue(issues, CodeMissingRequired, "api"); wasFound {
		testContext.Fatalf("un .local n'a jamais de missing_required: %+v", issues)
	}
}

func TestAcceptsEmptyOverride(testContext *testing.T) {
	issues := Validate("config.yaml.local", []byte(""))

	if len(issues) != 0 {
		testContext.Fatalf("valeurObtenue=%+v, attendu aucun probleme", issues)
	}
}

func TestMainConfigRequiresCoreSections(testContext *testing.T) {
	issues := Validate("config.yaml", []byte("prometheus:\n  enabled: true\n"))

	if _, wasFound := findIssue(issues, CodeMissingRequired, "common"); !wasFound {
		testContext.Fatalf("common requis hors .local: %+v", issues)
	}
}

func TestValidatesProfilesAsListOfMappings(testContext *testing.T) {
	content := []byte("name: ip_remediation\nfilters:\n  - Alert.Remediation == true\ndecisions:\n  - type: ban\n    duration: 4h\non_success: break\n---\nfilters: not_a_list\ndecisions: []\n")

	issues := Validate("profiles.yaml", content)

	if _, wasFound := findIssue(issues, CodeMissingRequired, "name"); !wasFound {
		testContext.Fatalf("name requis dans le 2e document: %+v", issues)
	}
	if _, wasFound := findIssue(issues, CodeWrongType, "filters"); !wasFound {
		testContext.Fatalf("filters doit etre une liste: %+v", issues)
	}
	if len(issues) != 2 {
		testContext.Fatalf("le 1er document est valide, valeurObtenue=%+v", issues)
	}
}

func TestValidatesAcquisitionRequiresSourceKey(testContext *testing.T) {
	content := []byte("source: docker\ncontainer_name_regexp:\n  - .*nginx.*\nlabels:\n  type: nginx\n---\nfilenames:\n  - /var/log/a.log\nlabels:\n  type: syslog\n")

	issues := Validate("acquis.d/web.yaml", content)

	missingSource, wasFound := findIssue(issues, CodeMissingRequired, "source")
	if !wasFound || missingSource.Line != 7 {
		testContext.Fatalf("source requis dans le 2e document: %+v", issues)
	}
	if _, wasFound := findIssue(issues, CodeUnknownKey, "container_name_regexp"); wasFound {
		testContext.Fatalf("cle docker connue: %+v", issues)
	}
}

func TestValidatesWhitelistRequiresNameAndWhitelist(testContext *testing.T) {
	validContent := []byte("name: my/whitelist\ndescription: mine\nwhitelist:\n  reason: lan\n  cidr:\n    - 10.0.0.0/8\n")
	invalidContent := []byte("description: mine\n")

	validIssues := Validate("parsers/s02-enrich/my-whitelist.yaml", validContent)
	invalidIssues := Validate("postoverflows/s01-whitelist/x.yaml", invalidContent)

	if len(validIssues) != 0 {
		testContext.Fatalf("whitelist valide, valeurObtenue=%+v", validIssues)
	}
	for _, requiredPath := range []string{"name", "whitelist"} {
		if _, wasFound := findIssue(invalidIssues, CodeMissingRequired, requiredPath); !wasFound {
			testContext.Fatalf("%s requis: %+v", requiredPath, invalidIssues)
		}
	}
}
