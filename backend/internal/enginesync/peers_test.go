package enginesync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPeersYAML = `peers:
  - name: edge-1
    url: https://engine-one.example.com:8080
    machine_id: dashboard
    password: peer-secret-password
    public_ips: [203.0.113.10, 2001:db8::10]
  - name: lab
    url: http://198.51.100.20:8080
    allow_insecure_http: true
    machine_id: dashboard
    password: another-secret-password
exclude:
  - 203.0.113.0/24
`

func writePeersFile(testContext *testing.T, content string) string {
	testContext.Helper()
	peersPath := filepath.Join(testContext.TempDir(), "peers.yaml")
	if writeError := os.WriteFile(peersPath, []byte(content), 0o600); writeError != nil {
		testContext.Fatalf("write peers file: %v", writeError)
	}
	return peersPath
}

func peerYAML(name string, url string, extraLines string) string {
	return "peers:\n  - name: " + name + "\n    url: " + url + "\n    machine_id: dashboard\n    password: long-enough-password\n" + extraLines
}

func TestLoadPeersParsesValidFile(testContext *testing.T) {
	peerSet, loadError := LoadPeers(writePeersFile(testContext, validPeersYAML))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if len(peerSet.Peers) != 2 || peerSet.Peers[0].Name != "edge-1" || peerSet.Peers[0].Password != "peer-secret-password" {
		testContext.Fatalf("unexpected peers: %d, first %q", len(peerSet.Peers), peerSet.Peers[0].Name)
	}
	if len(peerSet.Peers[0].PublicIPs) != 2 || peerSet.Peers[0].PublicIPs[0].String() != "203.0.113.10" {
		testContext.Fatalf("unexpected public ips %v", peerSet.Peers[0].PublicIPs)
	}
	if !peerSet.Peers[1].AllowInsecureHTTP {
		testContext.Error("allow_insecure_http must be read")
	}
	if len(peerSet.Exclude) != 1 || peerSet.Exclude[0].String() != "203.0.113.0/24" {
		testContext.Fatalf("unexpected exclude %v", peerSet.Exclude)
	}
}

func TestLoadPeersRejectsDuplicateNames(testContext *testing.T) {
	content := peerYAML("edge-1", "https://one.example.com", "") +
		"  - name: edge-1\n    url: https://two.example.com\n    machine_id: dashboard\n    password: long-enough-password\n"

	_, loadError := LoadPeers(writePeersFile(testContext, content))

	if loadError == nil {
		testContext.Fatal("expected an error for duplicate names")
	}
}

func TestLoadPeersRejectsReservedNameLocal(testContext *testing.T) {
	_, loadError := LoadPeers(writePeersFile(testContext, peerYAML("local", "https://one.example.com", "")))

	if loadError == nil {
		testContext.Fatal("expected an error for the reserved name local")
	}
}

func TestLoadPeersRejectsInvalidNames(testContext *testing.T) {
	for _, badName := range []string{"Edge", "-edge", "edge_1", strings.Repeat("a", 33)} {
		_, loadError := LoadPeers(writePeersFile(testContext, peerYAML(badName, "https://one.example.com", "")))
		if loadError == nil {
			testContext.Errorf("expected an error for name %q", badName)
		}
	}
	_, loadError := LoadPeers(writePeersFile(testContext, peerYAML(strings.Repeat("a", 32), "https://one.example.com", "")))
	if loadError != nil {
		testContext.Errorf("32 characters must be accepted: %v", loadError)
	}
}

func TestLoadPeersRequiresHTTPSUnlessAllowInsecure(testContext *testing.T) {
	_, refusedError := LoadPeers(writePeersFile(testContext, peerYAML("edge-1", "http://one.example.com", "")))
	if refusedError == nil {
		testContext.Fatal("http must be refused without allow_insecure_http")
	}
	_, acceptedError := LoadPeers(writePeersFile(testContext, peerYAML("edge-1", "http://one.example.com", "    allow_insecure_http: true\n")))
	if acceptedError != nil {
		testContext.Fatalf("http must be accepted with allow_insecure_http: %v", acceptedError)
	}
	_, schemeError := LoadPeers(writePeersFile(testContext, peerYAML("edge-1", "ftp://one.example.com", "    allow_insecure_http: true\n")))
	if schemeError == nil {
		testContext.Fatal("other schemes must be refused")
	}
}

func TestLoadPeersRejectsUnsafeURLs(testContext *testing.T) {
	for _, badURL := range []string{
		"https://user:topsecret@one.example.com",
		"https://one.example.com/?token=abc",
		"https://one.example.com/#frag",
		"https://",
		"one.example.com",
	} {
		_, loadError := LoadPeers(writePeersFile(testContext, peerYAML("edge-1", badURL, "")))
		if loadError == nil {
			testContext.Errorf("expected an error for url %q", badURL)
		}
	}
}

func TestLoadPeersRequiresCredentials(testContext *testing.T) {
	missingMachine := "peers:\n  - name: edge-1\n    url: https://one.example.com\n    password: long-enough-password\n"
	missingPassword := "peers:\n  - name: edge-1\n    url: https://one.example.com\n    machine_id: dashboard\n"
	shortPassword := "peers:\n  - name: edge-1\n    url: https://one.example.com\n    machine_id: dashboard\n    password: short\n"
	for _, content := range []string{missingMachine, missingPassword, shortPassword} {
		_, loadError := LoadPeers(writePeersFile(testContext, content))
		if loadError == nil {
			testContext.Errorf("expected an error for %q", content)
		}
	}
}

func TestLoadPeersRejectsInvalidAddressesAndPrefixes(testContext *testing.T) {
	_, ipError := LoadPeers(writePeersFile(testContext, peerYAML("edge-1", "https://one.example.com", "    public_ips: [not-an-ip]\n")))
	if ipError == nil {
		testContext.Error("expected an error for an invalid public ip")
	}
	_, cidrError := LoadPeers(writePeersFile(testContext, peerYAML("edge-1", "https://one.example.com", "")+"exclude: [not-a-cidr]\n"))
	if cidrError == nil {
		testContext.Error("expected an error for an invalid exclude")
	}
}

func TestLoadPeersRejectsTooManyPeers(testContext *testing.T) {
	var builder strings.Builder
	builder.WriteString("peers:\n")
	for peerIndex := 0; peerIndex < 17; peerIndex++ {
		builder.WriteString("  - name: peer-" + string(rune('a'+peerIndex)) + "\n    url: https://one.example.com\n    machine_id: dashboard\n    password: long-enough-password\n")
	}

	_, loadError := LoadPeers(writePeersFile(testContext, builder.String()))

	if loadError == nil {
		testContext.Fatal("expected an error for more than 16 peers")
	}
}

func TestLoadPeersRejectsUnknownFields(testContext *testing.T) {
	topLevel := validPeersYAML + "surprise: true\n"
	perPeer := peerYAML("edge-1", "https://one.example.com", "    pasword: typo\n")
	for _, content := range []string{topLevel, perPeer} {
		_, loadError := LoadPeers(writePeersFile(testContext, content))
		if loadError == nil {
			testContext.Errorf("expected an error for unknown field in %q", content)
		}
	}
}

func TestLoadPeersRejectsFileTooLarge(testContext *testing.T) {
	content := validPeersYAML + "# " + strings.Repeat("x", 64*1024) + "\n"

	_, loadError := LoadPeers(writePeersFile(testContext, content))

	if loadError == nil {
		testContext.Fatal("expected an error for a file above 64 KiB")
	}
}

func TestLoadPeersRejectsNonRegularFile(testContext *testing.T) {
	_, directoryError := LoadPeers(testContext.TempDir())
	if directoryError == nil {
		testContext.Error("expected an error for a directory")
	}
	_, missingError := LoadPeers(filepath.Join(testContext.TempDir(), "absent.yaml"))
	if missingError == nil {
		testContext.Error("expected an error for a missing file")
	}
}

func TestLoadPeersErrorNeverEchoesPassword(testContext *testing.T) {
	secretPassword := "hunter2-very-secret"
	secretURL := "https://operator:urlsecret@one.example.com/path?token=querysecret"
	cases := map[string]string{
		"credentials in url": "peers:\n  - name: edge-1\n    url: " + secretURL + "\n    machine_id: dashboard\n    password: " + secretPassword + "\n",
		"type mismatch":      "peers:\n  - name: edge-1\n    url: https://one.example.com\n    machine_id: dashboard\n    password: " + secretPassword + "\n    allow_insecure_http: " + secretPassword + "\n",
		"unknown field":      "peers:\n  - name: edge-1\n    url: https://one.example.com\n    machine_id: dashboard\n    password: " + secretPassword + "\n    extra: " + secretPassword + "\n",
		"duplicate":          "peers:\n  - name: edge-1\n    url: https://a.example.com\n    machine_id: dashboard\n    password: " + secretPassword + "\n  - name: edge-1\n    url: https://b.example.com\n    machine_id: dashboard\n    password: " + secretPassword + "\n",
		"http without flag":  "peers:\n  - name: edge-1\n    url: http://one.example.com\n    machine_id: dashboard\n    password: " + secretPassword + "\n",
		"syntax":             "peers: [\n  password: " + secretPassword + "\n",
	}
	for caseName, content := range cases {
		_, loadError := LoadPeers(writePeersFile(testContext, content))
		if loadError == nil {
			testContext.Errorf("%s: expected an error", caseName)
			continue
		}
		for _, forbidden := range []string{secretPassword, "urlsecret", "querysecret", "operator"} {
			if strings.Contains(loadError.Error(), forbidden) {
				testContext.Errorf("%s: error leaks %q: %v", caseName, forbidden, loadError)
			}
		}
	}
}

func TestPeerFormattingNeverPrintsPassword(testContext *testing.T) {
	secretPassword := "hunter2-very-secret"
	peer := Peer{Name: "edge-1", URL: "https://operator:urlsecret@one.example.com", MachineID: "dashboard", Password: secretPassword}
	type wrapper struct {
		Inner Peer
		Peers []Peer
	}
	outputs := map[string]string{
		"%v":       fmt.Sprintf("%v", peer),
		"%+v":      fmt.Sprintf("%+v", peer),
		"%#v":      fmt.Sprintf("%#v", peer),
		"%s":       fmt.Sprintf("%s", peer),
		"pointer":  fmt.Sprintf("%+v", &peer),
		"slice":    fmt.Sprintf("%+v", []Peer{peer}),
		"wrapper":  fmt.Sprintf("%+v", wrapper{Inner: peer, Peers: []Peer{peer}}),
		"entry":    fmt.Sprintf("%+v", peerEntry{Name: "edge-1", Password: secretPassword}),
		"document": fmt.Sprintf("%+v", peersDocument{Peers: []peerEntry{{Password: secretPassword}}}),
		"peer set": fmt.Sprintf("%+v", PeerSet{Peers: []Peer{peer}}),
	}
	var logBuffer bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuffer, nil)).Info("peer", "peer", peer)
	outputs["slog text"] = logBuffer.String()
	var jsonLogBuffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&jsonLogBuffer, nil)).Info("peer", "peer", peer)
	outputs["slog json"] = jsonLogBuffer.String()
	peerJSON, peerJSONError := json.Marshal(peer)
	if peerJSONError != nil {
		testContext.Fatalf("marshal peer: %v", peerJSONError)
	}
	outputs["json"] = string(peerJSON)
	wrapperJSON, wrapperJSONError := json.Marshal(wrapper{Inner: peer, Peers: []Peer{peer}})
	if wrapperJSONError != nil {
		testContext.Fatalf("marshal wrapper: %v", wrapperJSONError)
	}
	outputs["json wrapper"] = string(wrapperJSON)

	for outputName, output := range outputs {
		for _, forbidden := range []string{secretPassword, "urlsecret", "operator"} {
			if strings.Contains(output, forbidden) {
				testContext.Errorf("%s leaks %q: %s", outputName, forbidden, output)
			}
		}
	}
	if !strings.Contains(outputs["%+v"], "[REDACTED]") {
		testContext.Errorf("expected a redaction marker, got %s", outputs["%+v"])
	}
}

func TestLoadPeersRejectsMultiDocument(testContext *testing.T) {
	content := validPeersYAML + "---\npeers: []\n"
	_, loadError := LoadPeers(writePeersFile(testContext, content))
	if loadError == nil {
		testContext.Fatal("expected an error for several YAML documents")
	}
}

func TestLoadPeersRejectsEmptyAndZeroPeers(testContext *testing.T) {
	for _, content := range []string{"", "   \n", "peers: null\n", "peers: []\n", "exclude: [203.0.113.0/24]\n"} {
		_, loadError := LoadPeers(writePeersFile(testContext, content))
		if loadError == nil {
			testContext.Errorf("expected an error for %q", content)
			continue
		}
		if !strings.Contains(loadError.Error(), "peers") {
			testContext.Errorf("error must cite the peers field: %v", loadError)
		}
	}
}

func TestLoadPeersRejectsDuplicateYAMLKeys(testContext *testing.T) {
	content := "peers:\n  - name: edge-1\n    name: edge-2\n    url: https://one.example.com\n    machine_id: dashboard\n    password: long-enough-password\n"
	_, loadError := LoadPeers(writePeersFile(testContext, content))
	if loadError == nil {
		testContext.Fatal("expected an error for a duplicated key")
	}
}

func TestLoadPeersFollowsSymlink(testContext *testing.T) {
	targetPath := writePeersFile(testContext, validPeersYAML)
	linkPath := filepath.Join(testContext.TempDir(), "link.yaml")
	if symlinkError := os.Symlink(targetPath, linkPath); symlinkError != nil {
		testContext.Fatalf("symlink: %v", symlinkError)
	}
	_, loadError := LoadPeers(linkPath)
	if loadError != nil {
		testContext.Fatalf("a symlinked peers file must load: %v", loadError)
	}
}

func TestLoadPeersSizeBoundary(testContext *testing.T) {
	base := validPeersYAML + "# "
	exactContent := base + strings.Repeat("x", 64*1024-len(base)-1) + "\n"
	if len(exactContent) != 64*1024 {
		testContext.Fatalf("fixture size %d", len(exactContent))
	}
	_, exactError := LoadPeers(writePeersFile(testContext, exactContent))
	if exactError != nil {
		testContext.Errorf("exactly 64 KiB must be accepted: %v", exactError)
	}
	_, oversizeError := LoadPeers(writePeersFile(testContext, exactContent+"x"))
	if oversizeError == nil {
		testContext.Error("64 KiB + 1 must be refused")
	}
}

func TestLoadPeersAcceptsIPv6URL(testContext *testing.T) {
	_, loadError := LoadPeers(writePeersFile(testContext, peerYAML("edge-1", "https://[2001:db8::1]:8443", "")))
	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
}

func TestLoadPeersNormalizesAddresses(testContext *testing.T) {
	content := peerYAML("edge-1", "https://one.example.com", "    public_ips: ['::ffff:203.0.113.5']\n") + "exclude: ['::ffff:203.0.113.0/120']\n"
	peerSet, loadError := LoadPeers(writePeersFile(testContext, content))
	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if peerSet.Peers[0].PublicIPs[0].String() != "203.0.113.5" || peerSet.Exclude[0].String() != "203.0.113.0/24" {
		testContext.Fatalf("addresses must be unmapped: %v %v", peerSet.Peers[0].PublicIPs, peerSet.Exclude)
	}
}

func TestLoadPeersRejectsIPv6Zone(testContext *testing.T) {
	_, loadError := LoadPeers(writePeersFile(testContext, peerYAML("edge-1", "https://one.example.com", "    public_ips: ['fe80::1%eth0']\n")))
	if loadError == nil {
		testContext.Fatal("expected an error for a zoned address")
	}
}

func TestLoadPeersRejectsDuplicateURLs(testContext *testing.T) {
	content := peerYAML("edge-1", "https://One.Example.com/", "") +
		"  - name: edge-2\n    url: https://one.example.com:443\n    machine_id: dashboard\n    password: long-enough-password\n"
	_, loadError := LoadPeers(writePeersFile(testContext, content))
	if loadError == nil {
		testContext.Fatal("expected an error for the same url under two names")
	}
	if !strings.Contains(loadError.Error(), "edge-1") || !strings.Contains(loadError.Error(), "edge-2") {
		testContext.Errorf("error must cite both peers: %v", loadError)
	}
	distinct := peerYAML("edge-1", "https://one.example.com:8443", "") +
		"  - name: edge-2\n    url: https://one.example.com\n    machine_id: dashboard\n    password: long-enough-password\n"
	_, distinctError := LoadPeers(writePeersFile(testContext, distinct))
	if distinctError != nil {
		testContext.Errorf("different ports are different urls: %v", distinctError)
	}
}
