package enginesync

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
)

const redactedMarker = "[REDACTED]"

func (peer Peer) String() string {
	return fmt.Sprintf("peer{name=%s host=%s machine_id=%s password=%s}", peer.Name, urlHost(peer.URL), peer.MachineID, redactedMarker)
}

func (peer Peer) GoString() string {
	return peer.String()
}

func (peer Peer) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, peer.String())
}

func (peer Peer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", peer.Name),
		slog.String("host", urlHost(peer.URL)),
		slog.String("machine_id", peer.MachineID),
		slog.String("password", redactedMarker),
	)
}

func (entry peerEntry) String() string {
	return fmt.Sprintf("peerEntry{name=%s host=%s password=%s}", entry.Name, urlHost(entry.URL), redactedMarker)
}

func (entry peerEntry) GoString() string {
	return entry.String()
}

func (entry peerEntry) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, entry.String())
}

func urlHost(rawURL string) string {
	parsedURL, parseError := url.Parse(rawURL)
	if parseError != nil {
		return ""
	}
	return parsedURL.Host
}

func (peer Peer) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name      string `json:"name"`
		URLHost   string `json:"url_host"`
		MachineID string `json:"machine_id"`
	}{peer.Name, urlHost(peer.URL), peer.MachineID})
}
