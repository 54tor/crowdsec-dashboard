package api

import (
	"testing"
	"time"
)

func TestViewAuditGate_nEnregistreQueLaPremiereLectureEtLesChangements(t *testing.T) {
	horlogeCourante := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	gate := newViewAuditGate(func() time.Time { return horlogeCourante })

	premiereLecture := gate.shouldRecord(1, "local", "src-a")
	secondeLecture := gate.shouldRecord(1, "local", "src-a")
	changementDeSource := gate.shouldRecord(1, "local", "src-b")
	changementDEngine := gate.shouldRecord(1, "edge", "src-b")
	autreCompte := gate.shouldRecord(2, "edge", "src-b")

	valeurAttendue := []bool{true, false, true, true, true}
	valeurObtenue := []bool{premiereLecture, secondeLecture, changementDeSource, changementDEngine, autreCompte}
	for indexCas := range valeurAttendue {
		if valeurObtenue[indexCas] != valeurAttendue[indexCas] {
			t.Fatalf("case %d: got %v, want %v", indexCas, valeurObtenue, valeurAttendue)
		}
	}
}

func TestViewAuditGate_enregistreDeNouveauApresDeuxMinutesDInactivite(t *testing.T) {
	horlogeCourante := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	gate := newViewAuditGate(func() time.Time { return horlogeCourante })
	gate.shouldRecord(1, "local", "src-a")

	horlogeCourante = horlogeCourante.Add(time.Minute)
	toujoursActif := gate.shouldRecord(1, "local", "src-a")
	horlogeCourante = horlogeCourante.Add(viewAuditIdleWindow + time.Second)
	apresInactivite := gate.shouldRecord(1, "local", "src-a")

	if toujoursActif || !apresInactivite {
		t.Fatalf("got active=%v afterIdle=%v, want false/true", toujoursActif, apresInactivite)
	}
}

func TestViewAuditGate_nInscritPasChaqueRafraichissementDeDeuxOngletsAlternes(t *testing.T) {
	horlogeCourante := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	gate := newViewAuditGate(func() time.Time { return horlogeCourante })
	nombreEntrees := 0

	for indexRafraichissement := 0; indexRafraichissement < 6; indexRafraichissement++ {
		horlogeCourante = horlogeCourante.Add(4 * time.Second)
		for _, sourceCourante := range []string{"src-a", "src-b"} {
			if gate.shouldRecord(1, "local", sourceCourante) {
				nombreEntrees++
			}
		}
	}

	if nombreEntrees != 2 {
		t.Fatalf("got %d audit entries, want 2", nombreEntrees)
	}
}
