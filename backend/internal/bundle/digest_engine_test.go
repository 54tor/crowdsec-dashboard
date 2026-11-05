package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// The same bundle planned against two engines can give the same actions (for
// instance a collection missing on both): the digest must still differ, or a
// preview confirmed for one engine could be applied to another.
func TestDigestBindsTheTargetEngine(testContext *testing.T) {
	imported := hubBundle(HubCollection{Name: "crowdsecurity/nginx", Version: "0.2"})
	planFor := func(targetEngine string) ImportPlan {
		fixture := newImportFixture()
		deps := fixture.deps()
		deps.TargetEngine = targetEngine
		plan, planError := PlanImport(context.Background(), deps, imported, []string{SectionHub})
		if planError != nil {
			testContext.Fatalf("plan for %q: %v", targetEngine, planError)
		}
		return plan
	}

	localPlan := planFor("")
	peerPlan := planFor("peer")
	otherPeerPlan := planFor("other-peer")

	if peerPlan.Digest == otherPeerPlan.Digest || peerPlan.Digest == localPlan.Digest {
		testContext.Errorf("each engine needs its own digest, got local %s peer %s other %s", localPlan.Digest, peerPlan.Digest, otherPeerPlan.Digest)
	}
	if planFor("peer").Digest != peerPlan.Digest {
		testContext.Errorf("the digest of the same engine must be stable")
	}
	// The local digest keeps the material it had before engines existed, so a
	// preview made by an older page still applies locally.
	if localPlan.Digest != digestWithoutEngine(testContext, localPlan) {
		testContext.Errorf("the local digest changed: %s", localPlan.Digest)
	}
}

func digestWithoutEngine(testContext *testing.T, plan ImportPlan) string {
	testContext.Helper()
	encoded, encodeError := json.Marshal(struct {
		Sections    []string         `json:"sections"`
		Hub         []HubAction      `json:"hub"`
		Decisions   []DecisionAction `json:"decisions"`
		Alerts      []AlertAction    `json:"alerts"`
		Config      []FileAction     `json:"config"`
		Skipped     []SkippedItem    `json:"skipped"`
		Warnings    []string         `json:"warnings"`
		Unavailable []string         `json:"unavailable"`
	}{plan.Sections, plan.Hub, plan.Decisions, plan.Alerts, plan.Config, plan.Skipped, plan.Warnings, plan.Unavailable})
	if encodeError != nil {
		testContext.Fatalf("encode: %v", encodeError)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
