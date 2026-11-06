package logtail

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTailFile_retourneLesNDernieresLignesDansLOrdre(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "app.log")
	writeFixtureFile(t, chemin, "a\nb\nc\nd\ne\n")

	lines, tailError := tailInRoot(filepath.Dir(chemin), filepath.Base(chemin), 3)

	if tailError != nil {
		t.Fatal(tailError)
	}
	valeurAttendue := []string{"c", "d", "e"}
	if !reflect.DeepEqual(lines.Lines, valeurAttendue) {
		t.Fatalf("got %v, want %v", lines.Lines, valeurAttendue)
	}
}

func TestTailFile_gardeUneDerniereLigneSansRetourALaLigne(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "app.log")
	writeFixtureFile(t, chemin, "a\nb\npartial")

	lines, tailError := tailInRoot(filepath.Dir(chemin), filepath.Base(chemin), 10)

	if tailError != nil {
		t.Fatal(tailError)
	}
	valeurAttendue := []string{"a", "b", "partial"}
	if !reflect.DeepEqual(lines.Lines, valeurAttendue) {
		t.Fatalf("got %v, want %v", lines.Lines, valeurAttendue)
	}
}

func TestTailFile_retourneUneListeVideSurUnFichierVide(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "empty.log")
	writeFixtureFile(t, chemin, "")

	lines, tailError := tailInRoot(filepath.Dir(chemin), filepath.Base(chemin), 10)

	if tailError != nil || len(lines.Lines) != 0 {
		t.Fatalf("got %v, %v", lines, tailError)
	}
}

func TestTailFile_litSeulementLaFinDUnGrosFichier(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "big.log")
	gros := bytes.Repeat([]byte("0123456789abcdef\n"), (20<<20)/17)
	if writeError := os.WriteFile(chemin, gros, 0o644); writeError != nil {
		t.Fatal(writeError)
	}

	lines, tailError := tailInRoot(filepath.Dir(chemin), filepath.Base(chemin), 5)

	if tailError != nil {
		t.Fatal(tailError)
	}
	if len(lines.Lines) != 5 || lines.BytesRead > 2*MaxResponseBytes {
		t.Fatalf("lines=%d bytesRead=%d", len(lines.Lines), lines.BytesRead)
	}
	if lines.FileSize != int64(len(gros)) {
		t.Fatalf("file size = %d, want %d", lines.FileSize, len(gros))
	}
}

func TestTailFile_remplaceLesOctetsNonUtf8(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "bin.log")
	writeFixtureFile(t, chemin, "ok \xff\xfe end\n")

	lines, tailError := tailInRoot(filepath.Dir(chemin), filepath.Base(chemin), 1)

	if tailError != nil {
		t.Fatal(tailError)
	}
	if lines.Lines[0] != "ok �� end" {
		t.Fatalf("got %q", lines.Lines[0])
	}
}

func TestTailInRoot_refuseUnLienSymboliqueSortantDeLaRacine(t *testing.T) {
	racine := t.TempDir()
	dehors := filepath.Join(t.TempDir(), "outside.log")
	writeFixtureFile(t, dehors, "secret\n")
	if symlinkError := os.Symlink(dehors, filepath.Join(racine, "link.log")); symlinkError != nil {
		t.Fatal(symlinkError)
	}

	_, tailError := tailInRoot(racine, "link.log", 5)

	if tailError == nil {
		t.Fatal("expected the escaping symlink to be refused")
	}
}

func TestTailInRoot_ecarteLeFragmentInitialDUneLigneCoupeeParLaFenetre(t *testing.T) {
	racine := t.TempDir()
	writeFixtureFile(t, filepath.Join(racine, "long.log"), "token=SECRET"+strings.Repeat("z", 2*MaxResponseBytes)+"\n")

	lines, tailError := tailInRoot(racine, "long.log", 5)

	if tailError != nil {
		t.Fatal(tailError)
	}
	if len(lines.Lines) != 1 || lines.Lines[0] != lineTooLongMarker {
		t.Fatalf("got %d lines, first %q", len(lines.Lines), firstLine(lines.Lines))
	}
}

func firstLine(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[0][:min(len(lines[0]), 40)]
}
