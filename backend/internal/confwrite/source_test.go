package confwrite

import (
	"errors"
	"maps"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

// richFileAcquisition is an ordinary acquisition file: comments, quoted strings, lists, a nested
// labels mapping, an integer and booleans, all resolved implicitly.
const richFileAcquisition = `# nginx access and error logs
source: file
filenames:
  - /var/log/nginx/access.log
  - '/var/log/nginx/error.log'
force_inotify: true
poll_without_inotify: false
max_buffer_size: 65536
mode: tail
labels:
  type: "nginx"
  env: prod # inline comment
`

func TestOnlyFileJournalctlAndDockerSourcesAreAccepted(testContext *testing.T) {
	acceptedContents := map[string]string{
		"file":        "source: file\nfilenames: [/var/log/nginx/access.log]\nlabels: {type: nginx}\n",
		"journalctl":  "source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=ssh.service]\nlabels: {type: syslog}\n",
		"docker":      "source: docker\ncontainer_name: [web]\nlabels: {type: nginx}\n",
		"multi-doc":   "source: file\nfilenames: [/var/log/a.log]\nlabels: {type: syslog}\n---\nsource: docker\ncontainer_name: [web]\nlabels: {type: nginx}\n",
		"rich file":   richFileAcquisition,
		"rich docker": "source: docker\ncontainer_name:\n  - web\n  - \"api\"\ncheck_interval: 10s\nfollow_stdout: true\nfollow_stderr: false\nlabels:\n  type: nginx\n",
	}
	for caseName, content := range acceptedContents {
		if validationError := ValidateContent([]byte(content)); validationError != nil {
			testContext.Errorf("%s: expected accepted, got %v", caseName, validationError)
		}
	}
	refusedContents := map[string]string{
		"http":              "source: http\nlisten_addr: 0.0.0.0:8080\nlabels: {type: nginx}\n",
		"syslog":            "source: syslog\nlisten_addr: 0.0.0.0\nlabels: {type: syslog}\n",
		"appsec":            "source: appsec\nlisten_addr: 0.0.0.0:7422\nappsec_config: crowdsecurity/virtual-patching\nlabels: {type: appsec}\n",
		"kafka":             "source: kafka\nbrokers: [kafka:9092]\ntopic: logs\nlabels: {type: nginx}\n",
		"s3":                "source: s3\nbucket_name: logs\nlabels: {type: nginx}\n",
		"loki":              "source: loki\nurl: http://loki.example.com:3100\nlabels: {type: nginx}\n",
		"cloudwatch":        "source: cloudwatch\ngroup_name: logs\nlabels: {type: nginx}\n",
		"k8s-audit":         "source: k8s-audit\nlisten_addr: 0.0.0.0\nlabels: {type: k8s-audit}\n",
		"missing source":    "filenames: [/var/log/a.log]\nlabels: {type: syslog}\n",
		"empty source":      "source: \"\"\nlabels: {type: syslog}\n",
		"capitalised value": "source: File\nfilenames: [/var/log/a.log]\n",
		"source not scalar": "source: [file]\nfilenames: [/var/log/a.log]\n",
		"duplicate source":  "source: file\nsource: http\nfilenames: [/var/log/a.log]\n",
		"capitalised key":   "Source: http\nsource: file\nfilenames: [/var/log/a.log]\n",
		"transform key":     "source: file\nfilenames: [/var/log/a.log]\ntransform: 'evt.Line.Raw'\nlabels: {type: syslog}\n",
		"second document":   "source: file\nfilenames: [/var/log/a.log]\nlabels: {type: syslog}\n---\nsource: http\nlisten_addr: 0.0.0.0:8080\n",
		"empty document":    "source: file\nfilenames: [/var/log/a.log]\n---\n",
		"not a mapping":     "- source: file\n",
		"merged transform":  "source: file\nfilenames: [/var/log/a.log]\n<<: {transform: 'evt.Line.Raw'}\n",
		"merged list":       "source: file\nfilenames: [/var/log/a.log]\n<<: [{transform: 'evt.Line.Raw'}]\n",
		"merge-only source": "<<: {source: file}\nfilenames: [/var/log/a.log]\n",
		"tagged merge key":  "source: file\n!!merge x: {transform: 'evt.Line.Raw'}\n",
		"nested merge":      "source: file\nlabels:\n  <<: {type: syslog}\n",
		// Structural rule: keys must be plain, untagged !!str scalars and no node may carry an
		// explicit tag, so no tag can turn into a key CrowdSec would read differently.
		"binary key":          "source: file\nfilenames: [/var/log/a.log]\n!!binary dHJhbnNmb3Jt: evt.Line.Raw\n",
		"explicitly str key":  "source: file\n!!str filenames: [/var/log/a.log]\n",
		"custom tag":          "source: file\nfilenames: !foo [/var/log/a.log]\n",
		"sequence key":        "source: file\n? [transform]\n: evt.Line.Raw\n",
		"mapping key":         "source: file\n? {transform: x}\n: y\n",
		"integer key":         "source: file\n1: x\n",
		"null key":            "source: file\n~: x\n",
		"bool key":            "source: file\ntrue: x\n",
		"tagged value":        "source: file\nfilenames: !!str /var/log/a.log\n",
		"tagged nested value": "source: file\nfilenames: [/var/log/a.log]\nlabels: {type: !!str nginx}\n",
		"tagged source value": "source: !!str file\nfilenames: [/var/log/a.log]\n",
	}
	for caseName, content := range refusedContents {
		if validationError := ValidateContent([]byte(content)); !errors.Is(validationError, ErrForbiddenSource) {
			testContext.Errorf("%s: expected ErrForbiddenSource, got %v", caseName, validationError)
		}
	}
}

// TestAcceptedKeysAreTheKeysAGenericDecoderSees decodes accepted files the way CrowdSec does
// (yaml unmarshal of each document) and checks it sees exactly the keys the validator read:
// no tag-driven key transformation remains once only plain untagged string keys pass.
func TestAcceptedKeysAreTheKeysAGenericDecoderSees(testContext *testing.T) {
	for _, content := range []string{richFileAcquisition, "source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=ssh.service]\n"} {
		if validationError := ValidateContent([]byte(content)); validationError != nil {
			testContext.Fatalf("expected accepted, got %v", validationError)
		}
		var document yaml.Node
		var decoded map[string]any
		if yaml.Unmarshal([]byte(content), &document) != nil || yaml.Unmarshal([]byte(content), &decoded) != nil {
			testContext.Fatal("decode failed")
		}
		mapping := document.Content[0]
		validatedKeys := []string{}
		for keyIndex := 0; keyIndex < len(mapping.Content); keyIndex += 2 {
			validatedKeys = append(validatedKeys, mapping.Content[keyIndex].Value)
		}
		decodedKeys := slices.Sorted(maps.Keys(decoded))
		slices.Sort(validatedKeys)
		if !slices.Equal(validatedKeys, decodedKeys) {
			testContext.Errorf("validated %v, decoder sees %v", validatedKeys, decodedKeys)
		}
	}
}

func TestForbiddenSourceRefusesTheWholeFile(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	content := "source: file\nfilenames: [/var/log/a.log]\nlabels: {type: syslog}\n---\nsource: appsec\nlisten_addr: 0.0.0.0:7422\n"
	_, applyError := Apply(importDirectory, []FileChange{
		{Name: "ssh.yaml", Content: []byte(createdAcquisition)},
		{Name: "mixed.yaml", Content: []byte(content)},
	}, passingConfigTest)
	if !errors.Is(applyError, ErrForbiddenSource) {
		testContext.Fatalf("expected ErrForbiddenSource, got %v", applyError)
	}
	if len(directorySnapshot(testContext, importDirectory)) != 0 {
		testContext.Error("a forbidden source must write nothing at all")
	}
}
