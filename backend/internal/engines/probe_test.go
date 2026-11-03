package engines

import (
	"context"
	"testing"
)

// A stored secret that cannot be opened is an engine-side condition, not a database
// outage: the connection test reports it with the same closed code the registry uses.
func TestProbeReportsAnUnreadableSecretWithItsOwnCode(testContext *testing.T) {
	fixture := newFixture(testContext)
	brokenEngine := mustCreate(testContext, fixture, insecureInput("edge-unreadable", "http://edge-unreadable.example.com"))
	if _, corruptError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_machine_password_key_id = 'unknown-key' WHERE engine_id = ?`, brokenEngine.ID); corruptError != nil {
		testContext.Fatalf("corrupt key id: %v", corruptError)
	}
	registry := newTestRegistry(testContext, fixture, nil)

	failureCode, probeError := registry.Probe(context.Background(), "edge-unreadable")

	if probeError != nil {
		testContext.Fatalf("an unreadable secret must not fail the probe itself: %v", probeError)
	}
	if failureCode != ErrorCodeSecretUnreadable {
		testContext.Fatalf("expected %s, got %q", ErrorCodeSecretUnreadable, failureCode)
	}
}
