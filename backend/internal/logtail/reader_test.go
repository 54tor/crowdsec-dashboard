package logtail

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newReaderWithLog(t *testing.T, contenu string) (Reader, Source, string) {
	t.Helper()
	fixture := newAcquisitionFixture(t)
	logPath := filepath.Join(fixture.logsDir, "app.log")
	writeFixtureFile(t, logPath, contenu)
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "filename: "+logPath+"\n")
	reader := Reader{ConfDir: fixture.confDir, AllowedRoots: fixture.rootsDir}
	listing, listError := reader.List()
	if listError != nil || len(listing.Sources) != 1 {
		t.Fatalf("setup: %v %v", listing, listError)
	}
	return reader, listing.Sources[0], logPath
}

func TestReader_retourneLesDernieresLignesDUneSource(t *testing.T) {
	reader, source, _ := newReaderWithLog(t, "one\ntwo\nthree\n")

	lines, readError := reader.Read(source.ID, 2)

	if readError != nil {
		t.Fatal(readError)
	}
	if len(lines.Lines) != 2 || lines.Lines[1] != "three" {
		t.Fatalf("got %v", lines.Lines)
	}
}

func TestReader_bornePanierDeLignesAMaxLinesEtDefautACent(t *testing.T) {
	reader, source, _ := newReaderWithLog(t, strings.Repeat("l\n", 700))

	borne, boundError := reader.Read(source.ID, 10_000)
	defaut, defaultError := reader.Read(source.ID, 0)

	if boundError != nil || defaultError != nil {
		t.Fatal(boundError, defaultError)
	}
	if len(borne.Lines) != MaxLines || len(defaut.Lines) != DefaultLines {
		t.Fatalf("bounded=%d default=%d", len(borne.Lines), len(defaut.Lines))
	}
}

func TestReader_tronqueUneLigneDeDixMioAMaxLineBytes(t *testing.T) {
	reader, source, _ := newReaderWithLog(t, strings.Repeat("a", 10<<20)+"\n")

	lines, readError := reader.Read(source.ID, 1)

	if readError != nil {
		t.Fatal(readError)
	}
	if len(lines.Lines) != 1 || len(lines.Lines[0]) > MaxLineBytes+len(truncationMarker) {
		t.Fatalf("lines = %d", len(lines.Lines))
	}
}

func TestReader_tronqueUneLigneLongueMaisCompleteAMaxLineBytes(t *testing.T) {
	reader, source, _ := newReaderWithLog(t, strings.Repeat("a", 3*MaxLineBytes)+"\n")

	lines, readError := reader.Read(source.ID, 1)

	if readError != nil {
		t.Fatal(readError)
	}
	if !lines.Truncated || !strings.HasSuffix(lines.Lines[0], truncationMarker) {
		t.Fatalf("expected a truncated line, got truncated=%v", lines.Truncated)
	}
}

func TestReader_masqueAvantTroncatureUnTokenCoupeParLaLimite(t *testing.T) {
	padding := strings.Repeat("p", MaxLineBytes-10)
	reader, source, _ := newReaderWithLog(t, padding+" token=SUPERSECRETVALUE tail\n")

	lines, readError := reader.Read(source.ID, 1)

	if readError != nil {
		t.Fatal(readError)
	}
	if strings.Contains(lines.Lines[0], "SUPER") {
		t.Fatalf("secret leaked: %q", lines.Lines[0][len(lines.Lines[0])-30:])
	}
}

func TestReader_retourneErrSourceNotFoundPourUnIdentifiantInconnu(t *testing.T) {
	reader, _, _ := newReaderWithLog(t, "x\n")

	_, readError := reader.Read(strings.Repeat("0", 32), 5)

	if !errors.Is(readError, ErrSourceNotFound) {
		t.Fatalf("error = %v", readError)
	}
}

func TestReader_retourneErrSourceNotFoundSiLeFichierADisparu(t *testing.T) {
	reader, source, logPath := newReaderWithLog(t, "x\n")
	if removeError := os.Remove(logPath); removeError != nil {
		t.Fatal(removeError)
	}

	_, readError := reader.Read(source.ID, 5)

	if !errors.Is(readError, ErrSourceNotFound) {
		t.Fatalf("error = %v", readError)
	}
}

func TestReader_retourneErrSourceUnreadableSansPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	reader, source, logPath := newReaderWithLog(t, "x\n")
	if chmodError := os.Chmod(logPath, 0o000); chmodError != nil {
		t.Fatal(chmodError)
	}

	_, readError := reader.Read(source.ID, 5)

	if !errors.Is(readError, ErrSourceUnreadable) {
		t.Fatalf("error = %v", readError)
	}
}

func TestReader_refuseUnFichierRemplaceParUnLienSortantDesRacines(t *testing.T) {
	reader, source, logPath := newReaderWithLog(t, "x\n")
	outsidePath := filepath.Join(t.TempDir(), "outside.log")
	writeFixtureFile(t, outsidePath, "secret\n")
	if removeError := os.Remove(logPath); removeError != nil {
		t.Fatal(removeError)
	}
	if symlinkError := os.Symlink(outsidePath, logPath); symlinkError != nil {
		t.Fatal(symlinkError)
	}

	_, readError := reader.Read(source.ID, 5)

	if !errors.Is(readError, ErrSourceNotFound) {
		t.Fatalf("error = %v", readError)
	}
}

func TestReader_retourneErrLogsDisabledSansRacine(t *testing.T) {
	reader := Reader{ConfDir: t.TempDir()}

	_, readError := reader.Read(strings.Repeat("0", 32), 5)

	if !errors.Is(readError, ErrLogsDisabled) {
		t.Fatalf("error = %v", readError)
	}
}
