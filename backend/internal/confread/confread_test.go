package confread

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeConfFile(testContext *testing.T, directory, relativePath, content string) {
	testContext.Helper()
	absolutePath := filepath.Join(directory, filepath.FromSlash(relativePath))
	if mkdirError := os.MkdirAll(filepath.Dir(absolutePath), 0o755); mkdirError != nil {
		testContext.Fatal(mkdirError)
	}
	if writeError := os.WriteFile(absolutePath, []byte(content), 0o600); writeError != nil {
		testContext.Fatal(writeError)
	}
}

func TestReadRejectsCredentialsFiles(testContext *testing.T) {
	confDir := testContext.TempDir()
	writeConfFile(testContext, confDir, "local_api_credentials.yaml", "password: hunter2\n")
	writeConfFile(testContext, confDir, "online_api_credentials.yaml", "password: hunter2\n")
	writeConfFile(testContext, confDir, "parsers/s02-enrich/mine_whitelist_credentials.yaml", "password: hunter2\n")
	writeConfFile(testContext, confDir, "acquis.d/extra_credentials.yaml", "password: hunter2\n")
	rejectedNames := []string{
		"local_api_credentials.yaml",
		"online_api_credentials.yaml",
		"parsers/s02-enrich/mine_whitelist_credentials.yaml",
		"acquis.d/extra_credentials.yaml",
	}

	for _, rejectedName := range rejectedNames {
		content, readError := Read(confDir, rejectedName)
		if !errors.Is(readError, ErrNotAllowed) || content != nil {
			testContext.Errorf("%s: expected ErrNotAllowed, got %v", rejectedName, readError)
		}
	}
	listedNames, listError := List(confDir)
	if listError != nil {
		testContext.Fatal(listError)
	}
	for _, listedName := range listedNames {
		if strings.Contains(listedName, "credentials") {
			testContext.Errorf("credentials file listed: %s", listedName)
		}
	}
}

func TestReadRejectsPathTraversal(testContext *testing.T) {
	parentDir := testContext.TempDir()
	confDir := filepath.Join(parentDir, "crowdsec")
	writeConfFile(testContext, parentDir, "config.yaml", "secret: outside\n")
	writeConfFile(testContext, confDir, "config.yaml", "common:\n  log_level: info\n")
	rejectedNames := []string{
		"../config.yaml",
		"acquis.d/../../config.yaml",
		"/etc/passwd",
		"/config.yaml",
		"parsers/../../config.yaml",
		"config.yaml\x00.txt",
		"acquis.d\\..\\config.yaml",
		"",
		".",
		"./config.yaml",
		"unknown.yaml",
	}

	for _, rejectedName := range rejectedNames {
		content, readError := Read(confDir, rejectedName)
		if !errors.Is(readError, ErrNotAllowed) || content != nil {
			testContext.Errorf("%q: expected ErrNotAllowed, got %v", rejectedName, readError)
		}
	}
}

func TestReadRejectsSymlinkLeavingTheDirectory(testContext *testing.T) {
	parentDir := testContext.TempDir()
	confDir := filepath.Join(parentDir, "crowdsec")
	writeConfFile(testContext, parentDir, "outside.yaml", "name: outside\n")
	writeConfFile(testContext, confDir, "config.yaml", "name: inside\n")
	if symlinkError := os.Symlink(filepath.Join(parentDir, "outside.yaml"), filepath.Join(confDir, "profiles.yaml")); symlinkError != nil {
		testContext.Fatal(symlinkError)
	}

	content, readError := Read(confDir, "profiles.yaml")

	if readError == nil || content != nil {
		testContext.Fatalf("expected an error for an escaping symlink, got %q", content)
	}
	listedNames, listError := List(confDir)
	if listError != nil {
		testContext.Fatal(listError)
	}
	if slices.Contains(listedNames, "profiles.yaml") {
		testContext.Error("escaping symlink must not be listed")
	}
}

func TestReadRejectsOversizedFile(testContext *testing.T) {
	confDir := testContext.TempDir()
	writeConfFile(testContext, confDir, "config.yaml", strings.Repeat("a: b\n", MaxFileBytes/5+10))

	content, readError := Read(confDir, "config.yaml")

	if !errors.Is(readError, ErrTooLarge) || content != nil {
		testContext.Fatalf("expected ErrTooLarge, got %v", readError)
	}
}

func TestListReturnsOnlyWhitelistedFiles(testContext *testing.T) {
	confDir := testContext.TempDir()
	for _, relativePath := range []string{
		"config.yaml", "acquis.yaml", "profiles.yaml", "acquis.d/nginx.yaml", "acquis.d/notes.txt",
		"parsers/s02-enrich/mywhitelists.yaml", "parsers/s02-enrich/other.yaml", "parsers/s01-parse/custom-whitelist.yml",
		"local_api_credentials.yaml", "simulation.yaml", "notification/slack.yaml",
	} {
		writeConfFile(testContext, confDir, relativePath, "name: x\n")
	}

	listedNames, listError := List(confDir)

	if listError != nil {
		testContext.Fatal(listError)
	}
	expectedNames := []string{
		"acquis.d/nginx.yaml", "acquis.yaml", "config.yaml",
		"parsers/s01-parse/custom-whitelist.yml", "parsers/s02-enrich/mywhitelists.yaml", "profiles.yaml",
	}
	if !slices.Equal(listedNames, expectedNames) {
		testContext.Errorf("expected %v, got %v", expectedNames, listedNames)
	}
}

func TestReadRedactsSecretValues(testContext *testing.T) {
	confDir := testContext.TempDir()
	writeConfFile(testContext, confDir, "config.yaml", strings.Join([]string{
		"common:",
		"  log_level: info",
		"api:",
		"  server:",
		"    password: hunter2",
		"    API_KEY: abc123",
		"    auth_token: \"tok\"",
		"    client_secret: s3cr3t",
		"    ssh_key: AAAA",
		"    listen_uri: 127.0.0.1:8080",
		"  - token: listed",
		"",
	}, "\n"))

	content, readError := Read(confDir, "config.yaml")

	if readError != nil {
		testContext.Fatal(readError)
	}
	servedText := string(content)
	for _, leakedValue := range []string{"hunter2", "abc123", "tok\"", "s3cr3t", "AAAA", "listed"} {
		if strings.Contains(servedText, leakedValue) {
			testContext.Errorf("value %q leaked in %q", leakedValue, servedText)
		}
	}
	for _, keptText := range []string{"log_level: info", "listen_uri: 127.0.0.1:8080", "password: [REDACTED]"} {
		if !strings.Contains(servedText, keptText) {
			testContext.Errorf("expected %q in %q", keptText, servedText)
		}
	}
}

func TestReadRejectsCredentialsFilesCaseInsensitively(testContext *testing.T) {
	confDir := testContext.TempDir()
	writeConfFile(testContext, confDir, "parsers/s01-parse/my-whitelist_CREDENTIALS.yaml", "password: hunter2\n")
	writeConfFile(testContext, confDir, "acquis.d/Prod_Credentials.yaml", "password: hunter2\n")

	for _, rejectedName := range []string{"parsers/s01-parse/my-whitelist_CREDENTIALS.yaml", "acquis.d/Prod_Credentials.yaml"} {
		if _, readError := Read(confDir, rejectedName); !errors.Is(readError, ErrNotAllowed) {
			testContext.Errorf("%s: expected ErrNotAllowed, got %v", rejectedName, readError)
		}
	}
	listedNames, _ := List(confDir)
	if len(listedNames) != 0 {
		testContext.Errorf("nothing should be listed, got %v", listedNames)
	}
}

func TestSymlinksInsideTheDirectoryAreNeitherServedNorListed(testContext *testing.T) {
	confDir := testContext.TempDir()
	writeConfFile(testContext, confDir, "config.yaml", "name: real\n")
	writeConfFile(testContext, confDir, "other/extra.yaml", "name: extra\n")
	if symlinkError := os.Symlink("config.yaml", filepath.Join(confDir, "profiles.yaml")); symlinkError != nil {
		testContext.Fatal(symlinkError)
	}
	if symlinkError := os.Symlink("other", filepath.Join(confDir, "acquis.d")); symlinkError != nil {
		testContext.Fatal(symlinkError)
	}

	for _, refusedName := range []string{"profiles.yaml", "acquis.d/extra.yaml"} {
		if _, readError := Read(confDir, refusedName); !errors.Is(readError, ErrNotAllowed) {
			testContext.Errorf("%s: expected ErrNotAllowed, got %v", refusedName, readError)
		}
	}
	listedNames, listError := List(confDir)
	if listError != nil || !slices.Equal(listedNames, []string{"config.yaml"}) {
		testContext.Errorf("expected only config.yaml, got %v %v", listedNames, listError)
	}
}

// ReadUnredacted serves the raw content for a secrets export, so it must keep every path guard of Read.
func TestReadUnredactedKeepsSecretsAndThePathGuards(testContext *testing.T) {
	confDir := testContext.TempDir()
	writeConfFile(testContext, confDir, "profiles.yaml", "api_key: raw-value\n")
	writeConfFile(testContext, confDir, "local_api_credentials.yaml", "password: hunter2\n")

	rawContent, readError := ReadUnredacted(confDir, "profiles.yaml")
	if readError != nil || string(rawContent) != "api_key: raw-value\n" {
		testContext.Errorf("expected the raw content, got %q (%v)", rawContent, readError)
	}
	for _, rejectedName := range []string{"local_api_credentials.yaml", "../profiles.yaml"} {
		if content, rejectedError := ReadUnredacted(confDir, rejectedName); !errors.Is(rejectedError, ErrNotAllowed) || content != nil {
			testContext.Errorf("%s: expected ErrNotAllowed, got %v", rejectedName, rejectedError)
		}
	}
}

func TestPostoverflowWhitelistIsListed(testContext *testing.T) {
	confDir := testContext.TempDir()
	listedNames := []string{
		"postoverflows/s01-whitelist/my-whitelist.yaml",
		"postoverflows/s01-whitelist/other-whitelist.yml",
	}
	for _, listedName := range listedNames {
		writeConfFile(testContext, confDir, listedName, "name: example/whitelist\ndescription: \"x\"\npassword: hunter2\n")
	}

	obtainedNames, listError := List(confDir)
	if listError != nil {
		testContext.Fatal(listError)
	}
	if !slices.Equal(obtainedNames, listedNames) {
		testContext.Fatalf("expected %v, got %v", listedNames, obtainedNames)
	}
	for _, listedName := range listedNames {
		obtainedContent, readError := Read(confDir, listedName)
		if readError != nil {
			testContext.Fatalf("%s: %v", listedName, readError)
		}
		if strings.Contains(string(obtainedContent), "hunter2") {
			testContext.Errorf("%s: secret value must be redacted", listedName)
		}
	}
}

func TestPostoverflowNonWhitelistIsRefused(testContext *testing.T) {
	confDir := testContext.TempDir()
	refusedFiles := []string{
		"postoverflows/s01-whitelist/rules.yaml",
		"postoverflows/s01-whitelist/x-whitelist.txt",
		"postoverflows/s01-whitelist/whitelist",
		"postoverflows/s01-whitelist/sub/x-whitelist.yaml",
		"postoverflows/x-whitelist.yaml",
		"postoverflows/s01-whitelist/x-whitelist_credentials.yaml",
	}
	for _, refusedFile := range refusedFiles {
		writeConfFile(testContext, confDir, refusedFile, "name: example/refused\n")
	}
	refusedDirectory := "postoverflows/s01-whitelist/dir-whitelist.yaml"
	if mkdirError := os.MkdirAll(filepath.Join(confDir, refusedDirectory), 0o755); mkdirError != nil {
		testContext.Fatal(mkdirError)
	}
	refusedNames := append(slices.Clone(refusedFiles),
		refusedDirectory,
		"postoverflows/s01-whitelist/../../config.yaml",
		"postoverflows/../config.yaml",
		"../postoverflows/s01-whitelist/my-whitelist.yaml",
	)

	for _, refusedName := range refusedNames {
		obtainedContent, readError := Read(confDir, refusedName)
		if !errors.Is(readError, ErrNotAllowed) || obtainedContent != nil {
			testContext.Errorf("%q: expected ErrNotAllowed, got %v", refusedName, readError)
		}
	}
	obtainedNames, listError := List(confDir)
	if listError != nil {
		testContext.Fatal(listError)
	}
	if len(obtainedNames) != 0 {
		testContext.Errorf("expected nothing listed, got %v", obtainedNames)
	}
}

func TestHubSymlinkedWhitelistIsRefused(testContext *testing.T) {
	confDir := testContext.TempDir()
	hubDirectory := filepath.Join(confDir, "hub", "postoverflows", "s01-whitelist")
	writeConfFile(testContext, confDir, "hub/postoverflows/s01-whitelist/hub-whitelist.yaml", "name: example/hub\n")
	linkedFileDirectory := filepath.Join(confDir, "postoverflows", "s01-whitelist")
	if mkdirError := os.MkdirAll(linkedFileDirectory, 0o755); mkdirError != nil {
		testContext.Fatal(mkdirError)
	}
	fileSymlinkPath := filepath.Join(linkedFileDirectory, "hub-whitelist.yaml")
	if symlinkError := os.Symlink(filepath.Join(hubDirectory, "hub-whitelist.yaml"), fileSymlinkPath); symlinkError != nil {
		testContext.Fatal(symlinkError)
	}
	linkedDirectoryParent := filepath.Join(confDir, "postoverflows", "s02-whitelist")
	if symlinkError := os.Symlink(hubDirectory, linkedDirectoryParent); symlinkError != nil {
		testContext.Fatal(symlinkError)
	}

	refusedNames := []string{
		"postoverflows/s01-whitelist/hub-whitelist.yaml",
		"postoverflows/s02-whitelist/hub-whitelist.yaml",
	}
	for _, refusedName := range refusedNames {
		obtainedContent, readError := Read(confDir, refusedName)
		if !errors.Is(readError, ErrNotAllowed) || obtainedContent != nil {
			testContext.Errorf("%q: expected ErrNotAllowed, got %v", refusedName, readError)
		}
	}
	obtainedNames, listError := List(confDir)
	if listError != nil {
		testContext.Fatal(listError)
	}
	if len(obtainedNames) != 0 {
		testContext.Errorf("symlinked whitelists must not be listed, got %v", obtainedNames)
	}
}

func TestReadAllowsLocalOverrideConfigFile(testContext *testing.T) {
	confDir := testContext.TempDir()
	writeConfFile(testContext, confDir, "config.yaml.local", "api:\n  server:\n    listen_uri: 127.0.0.1:8080\n")
	if !IsAllowedName("config.yaml.local") {
		testContext.Fatal("config.yaml.local must be on the read allow-list")
	}
	listedNames, listError := List(confDir)
	if listError != nil || !slices.Contains(listedNames, "config.yaml.local") {
		testContext.Fatalf("List = %v, %v", listedNames, listError)
	}
	if _, readError := Read(confDir, "config.yaml.local"); readError != nil {
		testContext.Fatalf("Read: %v", readError)
	}
}
