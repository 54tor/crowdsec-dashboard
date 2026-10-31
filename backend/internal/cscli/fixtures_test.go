package cscli

import (
	"os"
	"path/filepath"
	"testing"
)

const frozenFixturesDirectory = "../../../deploy/dev/fixtures"

func readFrozenFixture(testContext *testing.T, fileName string) []byte {
	testContext.Helper()
	content, readError := os.ReadFile(filepath.Join(frozenFixturesDirectory, fileName))
	if readError != nil {
		testContext.Fatalf("read fixture %s: %v", fileName, readError)
	}
	return content
}

func TestDecodeListParsesFrozenFixtures(testContext *testing.T) {
	testCases := []struct {
		fixtureName     string
		identifierField string
		expectedCount   int
		expectedValue   string
	}{
		{"bouncers-list.json", "name", 1, "dev-firewall-bouncer"},
		{"machines-list.json", "machineId", 3, "dev-agent"},
		{"alerts-list.json", "scenario", 10, "crowdsecurity/ssh-slow-bf"},
		{"lapi-alerts.json", "scenario", 10, "seed range ban"},
	}
	for _, testCase := range testCases {
		testContext.Run(testCase.fixtureName, func(testContext *testing.T) {
			entries, decodeError := DecodeList[map[string]any](readFrozenFixture(testContext, testCase.fixtureName))
			if decodeError != nil {
				testContext.Fatalf("decode: %v", decodeError)
			}
			if len(entries) != testCase.expectedCount {
				testContext.Fatalf("expected %d entries, got %d", testCase.expectedCount, len(entries))
			}
			found := false
			for _, entry := range entries {
				found = found || entry[testCase.identifierField] == testCase.expectedValue
			}
			if !found {
				testContext.Fatalf("no entry with %s=%q", testCase.identifierField, testCase.expectedValue)
			}
		})
	}
}

func TestDecodeListTurnsNullIntoEmptyList(testContext *testing.T) {
	entries, decodeError := DecodeList[map[string]any]([]byte("null\n"))
	if decodeError != nil || entries == nil || len(entries) != 0 {
		testContext.Fatalf("expected an empty non-nil list, got %#v (%v)", entries, decodeError)
	}
}
