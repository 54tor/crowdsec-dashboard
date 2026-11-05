package engines

import (
	"context"
	"errors"
	"testing"
)

// The sidecar audience is the engine name: renaming an enrolled engine would
// make every signed request carry an audience its sidecar refuses, so the
// rename is refused until the sidecar is removed.
func TestRenamingAnEngineWithASidecarIsRefusedUntilTheSidecarIsRemoved(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)

	_, refusedRenameError := fixture.repository.Update(context.Background(), "edge-1", Input{Name: "edge-2"})
	if !errors.Is(refusedRenameError, ErrSidecarRenameRequiresRemoval) {
		testContext.Fatalf("expected ErrSidecarRenameRequiresRemoval, got %v", refusedRenameError)
	}
	keptEngine, keptEngineError := fixture.repository.Get(context.Background(), "edge-1")
	if keptEngineError != nil || keptEngine.Sidecar == nil {
		testContext.Fatalf("the refused rename must keep the engine and its sidecar, got %+v %v", keptEngine, keptEngineError)
	}

	_, sameNameError := fixture.repository.Update(context.Background(), "edge-1", Input{Name: "edge-1"})
	if sameNameError != nil {
		testContext.Errorf("submitting the unchanged name is not a rename, got %v", sameNameError)
	}

	if removeError := fixture.repository.RemoveSidecar(context.Background(), "edge-1"); removeError != nil {
		testContext.Fatalf("remove sidecar: %v", removeError)
	}
	renamedEngine, renameError := fixture.repository.Update(context.Background(), "edge-1", Input{Name: "edge-2"})
	if renameError != nil || renamedEngine.Name != "edge-2" {
		testContext.Errorf("expected the rename to succeed once the sidecar is removed, got %+v %v", renamedEngine, renameError)
	}
}
