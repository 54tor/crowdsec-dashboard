package api

import (
	"slices"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarclient"
)

func TestSidecarTransportSentinelsAreTheSharedListPlusTheTimeout(testContext *testing.T) {
	expectedSentinels := append(slices.Clone(sidecarclient.TransportSentinels()), cscli.ErrTimeout)

	if !slices.Equal(sidecarTransportSentinels, expectedSentinels) {
		testContext.Fatalf("expected %v, got %v", expectedSentinels, sidecarTransportSentinels)
	}
}
