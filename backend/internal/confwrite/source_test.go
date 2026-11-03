package confwrite

import (
	"errors"
	"testing"
)

func TestOnlyFileJournalctlAndDockerSourcesAreAccepted(testContext *testing.T) {
	acceptedContents := map[string]string{
		"file":       "source: file\nfilenames: [/var/log/nginx/access.log]\nlabels: {type: nginx}\n",
		"journalctl": "source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=ssh.service]\nlabels: {type: syslog}\n",
		"docker":     "source: docker\ncontainer_name: [web]\nlabels: {type: nginx}\n",
		"multi-doc":  "source: file\nfilenames: [/var/log/a.log]\nlabels: {type: syslog}\n---\nsource: docker\ncontainer_name: [web]\nlabels: {type: nginx}\n",
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
	}
	for caseName, content := range refusedContents {
		if validationError := ValidateContent([]byte(content)); !errors.Is(validationError, ErrForbiddenSource) {
			testContext.Errorf("%s: expected ErrForbiddenSource, got %v", caseName, validationError)
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
