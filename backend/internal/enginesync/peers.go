package enginesync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"

	"crowdsec-dashboard/internal/netparse"
	"go.yaml.in/yaml/v3"
)

const (
	maxPeersFileBytes = 64 * 1024
	maxPeers          = 16
	minPasswordLength = 8
	reservedLocalName = "local"
)

var (
	defaultPorts    = map[string]string{"https": "443", "http": "80"}
	peerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	yamlLinePattern = regexp.MustCompile(`line (\d+)`)
)

type Peer struct {
	Name              string
	URL               string
	MachineID         string
	Password          string `json:"-"`
	AllowInsecureHTTP bool
	PublicIPs         []netip.Addr
}

type PeerSet struct {
	Peers   []Peer
	Exclude []netip.Prefix
}

type peersDocument struct {
	Peers   []peerEntry `yaml:"peers"`
	Exclude []string    `yaml:"exclude"`
}

type peerEntry struct {
	Name              string   `yaml:"name"`
	URL               string   `yaml:"url"`
	MachineID         string   `yaml:"machine_id"`
	Password          string   `yaml:"password" json:"-"`
	AllowInsecureHTTP bool     `yaml:"allow_insecure_http"`
	PublicIPs         []string `yaml:"public_ips"`
}

func LoadPeers(path string) (PeerSet, error) {
	content, readError := readPeersFile(path)
	if readError != nil {
		return PeerSet{}, readError
	}
	document, decodeError := decodePeersDocument(content)
	if decodeError != nil {
		return PeerSet{}, decodeError
	}
	return buildPeerSet(document)
}

func readPeersFile(path string) ([]byte, error) {
	pathInfo, statError := os.Stat(path)
	if statError != nil {
		return nil, errors.New("peers file cannot be read")
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("peers file is not a regular file")
	}
	peersFile, openError := os.Open(path)
	if openError != nil {
		return nil, errors.New("peers file cannot be read")
	}
	defer peersFile.Close()
	openedInfo, openedStatError := peersFile.Stat()
	if openedStatError != nil || !openedInfo.Mode().IsRegular() {
		return nil, errors.New("peers file is not a regular file")
	}
	content, readError := io.ReadAll(io.LimitReader(peersFile, maxPeersFileBytes+1))
	if readError != nil {
		return nil, errors.New("peers file cannot be read")
	}
	if len(content) > maxPeersFileBytes {
		return nil, fmt.Errorf("peers file exceeds %d bytes", maxPeersFileBytes)
	}
	return content, nil
}

func decodePeersDocument(content []byte) (peersDocument, error) {
	var document peersDocument
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	decodeError := decoder.Decode(&document)
	if errors.Is(decodeError, io.EOF) {
		return peersDocument{}, errors.New("peers file is empty: field peers is required")
	}
	if decodeError == nil {
		var extraDocument any
		if !errors.Is(decoder.Decode(&extraDocument), io.EOF) {
			return peersDocument{}, errors.New("peers file must contain a single YAML document")
		}
		return document, nil
	}
	lineMatch := yamlLinePattern.FindStringSubmatch(decodeError.Error())
	if lineMatch == nil {
		return peersDocument{}, errors.New("peers file is not valid: syntax error, unknown field or wrong type")
	}
	return peersDocument{}, fmt.Errorf("peers file is not valid near line %s: syntax error, unknown field or wrong type", lineMatch[1])
}

func buildPeerSet(document peersDocument) (PeerSet, error) {
	if len(document.Peers) == 0 {
		return PeerSet{}, errors.New("peers file: field peers must list at least one peer")
	}
	if len(document.Peers) > maxPeers {
		return PeerSet{}, fmt.Errorf("peers file lists more than %d peers", maxPeers)
	}
	peerSet := PeerSet{}
	seenNames := make(map[string]bool, len(document.Peers))
	seenURLs := make(map[string]string, len(document.Peers))
	for peerIndex, entry := range document.Peers {
		peer, peerError := validatePeer(peerIndex, entry, seenNames)
		if peerError != nil {
			return PeerSet{}, peerError
		}
		urlKey := normalizedURLKey(peer.URL)
		if otherName, duplicated := seenURLs[urlKey]; duplicated {
			return PeerSet{}, fmt.Errorf("peers %q and %q: url is the same", otherName, peer.Name)
		}
		seenURLs[urlKey] = peer.Name
		seenNames[peer.Name] = true
		peerSet.Peers = append(peerSet.Peers, peer)
	}
	for _, rawPrefix := range document.Exclude {
		prefix, parseError := netparse.ParsePrefix(rawPrefix)
		if parseError != nil {
			return PeerSet{}, errors.New("exclude contains an invalid CIDR")
		}
		peerSet.Exclude = append(peerSet.Exclude, prefix)
	}
	return peerSet, nil
}

func validatePeer(peerIndex int, entry peerEntry, seenNames map[string]bool) (Peer, error) {
	if !peerNamePattern.MatchString(entry.Name) {
		return Peer{}, fmt.Errorf("peer #%d: name must match %s", peerIndex+1, peerNamePattern)
	}
	if entry.Name == reservedLocalName {
		return Peer{}, fmt.Errorf("peer %q: name is reserved", entry.Name)
	}
	if seenNames[entry.Name] {
		return Peer{}, fmt.Errorf("peer %q: name is duplicated", entry.Name)
	}
	if urlError := validatePeerURL(entry); urlError != nil {
		return Peer{}, fmt.Errorf("peer %q: url %w", entry.Name, urlError)
	}
	if entry.MachineID == "" {
		return Peer{}, fmt.Errorf("peer %q: machine_id is required", entry.Name)
	}
	if len(entry.Password) < minPasswordLength {
		return Peer{}, fmt.Errorf("peer %q: password is required and must have at least %d characters", entry.Name, minPasswordLength)
	}
	publicIPs, publicIPsError := parsePublicIPs(entry.PublicIPs)
	if publicIPsError != nil {
		return Peer{}, fmt.Errorf("peer %q: public_ips contains an invalid address", entry.Name)
	}
	return Peer{
		Name:              entry.Name,
		URL:               entry.URL,
		MachineID:         entry.MachineID,
		Password:          entry.Password,
		AllowInsecureHTTP: entry.AllowInsecureHTTP,
		PublicIPs:         publicIPs,
	}, nil
}

func validatePeerURL(entry peerEntry) error {
	parsedURL, parseError := url.Parse(entry.URL)
	if parseError != nil || parsedURL.Host == "" || parsedURL.Hostname() == "" {
		return errors.New("is not a valid absolute URL")
	}
	schemeAllowed := parsedURL.Scheme == "https" || (parsedURL.Scheme == "http" && entry.AllowInsecureHTTP)
	if !schemeAllowed {
		return errors.New("must use https unless allow_insecure_http is true")
	}
	if parsedURL.User != nil {
		return errors.New("must not contain credentials")
	}
	if parsedURL.RawQuery != "" || parsedURL.ForceQuery || parsedURL.Fragment != "" {
		return errors.New("must not contain a query or fragment")
	}
	return nil
}

func parsePublicIPs(rawAddresses []string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	for _, rawAddress := range rawAddresses {
		address, parseError := netparse.ParseAddr(rawAddress)
		if parseError != nil {
			return nil, parseError
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func normalizedURLKey(rawURL string) string {
	parsedURL, _ := url.Parse(rawURL)
	port := parsedURL.Port()
	if port == "" {
		port = defaultPorts[parsedURL.Scheme]
	}
	return parsedURL.Scheme + "://" + net.JoinHostPort(strings.ToLower(parsedURL.Hostname()), port) + strings.TrimRight(parsedURL.EscapedPath(), "/")
}
