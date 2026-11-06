package logtail

import (
	"os"
	"path/filepath"
	"testing"
)

type acquisitionFixture struct {
	confDir  string
	logsDir  string
	rootsDir []string
}

func newAcquisitionFixture(t *testing.T) acquisitionFixture {
	t.Helper()
	racine := t.TempDir()
	fixture := acquisitionFixture{
		confDir: filepath.Join(racine, "conf"),
		logsDir: filepath.Join(racine, "logs"),
	}
	for _, dossier := range []string{fixture.confDir, fixture.logsDir} {
		if erreur := os.MkdirAll(dossier, 0o755); erreur != nil {
			t.Fatal(erreur)
		}
	}
	fixture.rootsDir = []string{fixture.logsDir}
	return fixture
}

func writeFixtureFile(t *testing.T, chemin string, contenu string) {
	t.Helper()
	if erreur := os.MkdirAll(filepath.Dir(chemin), 0o755); erreur != nil {
		t.Fatal(erreur)
	}
	if erreur := os.WriteFile(chemin, []byte(contenu), 0o644); erreur != nil {
		t.Fatal(erreur)
	}
}

func labelsOf(sources []Source) []string {
	libelles := make([]string, 0, len(sources))
	for _, sourceCourante := range sources {
		libelles = append(libelles, sourceCourante.Label)
	}
	return libelles
}
