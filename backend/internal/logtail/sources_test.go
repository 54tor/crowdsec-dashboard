package logtail

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestListSources_retourneLesFichiersDeAcquisYamlEtAcquisD(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	nginxLog := filepath.Join(fixture.logsDir, "nginx.log")
	sshLog := filepath.Join(fixture.logsDir, "auth.log")
	writeFixtureFile(t, nginxLog, "a\n")
	writeFixtureFile(t, sshLog, "b\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "source: file\nfilenames:\n  - "+nginxLog+"\nlabels:\n  type: nginx\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.d", "ssh.yaml"), "source: file\nfilename: "+sshLog+"\nlabels:\n  type: syslog\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	valeurAttendue := []string{sshLog, nginxLog}
	valeurObtenue := labelsOf(listing.Sources)
	if !reflect.DeepEqual(valeurObtenue, valeurAttendue) {
		t.Fatalf("labels = %v, want %v", valeurObtenue, valeurAttendue)
	}
	if len(listing.Sources[0].ID) != 32 {
		t.Fatalf("ID %q should be 32 hex characters", listing.Sources[0].ID)
	}
}

func TestListSources_suitAcquisitionPathEtAcquisitionDirDuConfigYaml(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	customLog := filepath.Join(fixture.logsDir, "custom.log")
	ignoredLog := filepath.Join(fixture.logsDir, "ignored.log")
	writeFixtureFile(t, customLog, "x\n")
	writeFixtureFile(t, ignoredLog, "x\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "config.yaml"),
		"crowdsec_service:\n  acquisition_path: /etc/crowdsec/custom.yaml\n  acquisition_dir: /etc/crowdsec/custom.d\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "custom.yaml"), "filename: "+customLog+"\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "filename: "+ignoredLog+"\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	valeurAttendue := []string{customLog}
	if valeurObtenue := labelsOf(listing.Sources); !reflect.DeepEqual(valeurObtenue, valeurAttendue) {
		t.Fatalf("labels = %v, want %v", valeurObtenue, valeurAttendue)
	}
}

func TestListSources_lisLesDocumentsYamlMultiples(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	premierLog := filepath.Join(fixture.logsDir, "one.log")
	secondLog := filepath.Join(fixture.logsDir, "two.log")
	writeFixtureFile(t, premierLog, "x\n")
	writeFixtureFile(t, secondLog, "x\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"),
		"source: file\nfilename: "+premierLog+"\n---\nsource: file\nfilename: "+secondLog+"\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	if len(listing.Sources) != 2 {
		t.Fatalf("got %d sources, want 2", len(listing.Sources))
	}
}

func TestListSources_developpeLesGlobs(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	writeFixtureFile(t, filepath.Join(fixture.logsDir, "site-a.log"), "x\n")
	writeFixtureFile(t, filepath.Join(fixture.logsDir, "site-b.log"), "x\n")
	writeFixtureFile(t, filepath.Join(fixture.logsDir, "site-c.txt"), "x\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "filenames:\n  - "+fixture.logsDir+"/site-*.log\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	if len(listing.Sources) != 2 {
		t.Fatalf("got %v, want site-a and site-b", labelsOf(listing.Sources))
	}
}

func TestListSources_signaleLesSourcesNonFichierCommeIllisibles(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"),
		"source: docker\ncontainer_name:\n  - web\n---\nsource: journalctl\njournalctl_filter: [\"_SYSTEMD_UNIT=sshd.service\"]\n---\nsource: docker\ncontainer_name:\n  - api\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	valeurAttendue := []UnreadableSource{{Kind: "docker"}, {Kind: "journalctl"}}
	if !reflect.DeepEqual(listing.Unreadable, valeurAttendue) {
		t.Fatalf("unreadable = %v, want %v", listing.Unreadable, valeurAttendue)
	}
}

func TestListSources_dedoublonneLeMemeFichierAtteintParDeuxSources(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	sharedLog := filepath.Join(fixture.logsDir, "shared.log")
	writeFixtureFile(t, sharedLog, "x\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"),
		"filename: "+sharedLog+"\n---\nfilenames:\n  - "+fixture.logsDir+"/*.log\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	if len(listing.Sources) != 1 {
		t.Fatalf("got %v, want one source", labelsOf(listing.Sources))
	}
}

func TestListSources_refuseUnFichierHorsDesRacinesAutorisees(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	outsideLog := filepath.Join(t.TempDir(), "outside.log")
	writeFixtureFile(t, outsideLog, "x\n")
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "filename: "+outsideLog+"\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	if len(listing.Sources) != 0 {
		t.Fatalf("got %v, want none", labelsOf(listing.Sources))
	}
}

func TestListSources_refuseUnLienSymboliqueSortantDesRacines(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	outsideLog := filepath.Join(t.TempDir(), "secret.log")
	writeFixtureFile(t, outsideLog, "x\n")
	linkPath := filepath.Join(fixture.logsDir, "link.log")
	if symlinkError := os.Symlink(outsideLog, linkPath); symlinkError != nil {
		t.Fatal(symlinkError)
	}
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "filename: "+linkPath+"\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	if len(listing.Sources) != 0 {
		t.Fatalf("got %v, want none", labelsOf(listing.Sources))
	}
}

func TestListSources_ignoreLesFichiersNonReguliers(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	directoryPath := filepath.Join(fixture.logsDir, "subdir.log")
	if mkdirError := os.MkdirAll(directoryPath, 0o755); mkdirError != nil {
		t.Fatal(mkdirError)
	}
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "filename: "+directoryPath+"\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	if len(listing.Sources) != 0 {
		t.Fatalf("got %v, want none", labelsOf(listing.Sources))
	}
}

func TestListSources_plafonneAMaxSourcesEtMarqueTronque(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	for indexFichier := 0; indexFichier < MaxSources+5; indexFichier++ {
		writeFixtureFile(t, filepath.Join(fixture.logsDir, fmt.Sprintf("file-%03d.log", indexFichier)), "x\n")
	}
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "filenames:\n  - "+fixture.logsDir+"/*.log\n")

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil {
		t.Fatal(listError)
	}
	if len(listing.Sources) != MaxSources || !listing.Truncated {
		t.Fatalf("got %d sources truncated=%v", len(listing.Sources), listing.Truncated)
	}
}

func TestListSources_retourneErrLogsDisabledSansRacine(t *testing.T) {
	fixture := newAcquisitionFixture(t)

	_, listError := ListSources(fixture.confDir, nil)

	if !errors.Is(listError, ErrLogsDisabled) {
		t.Fatalf("error = %v, want ErrLogsDisabled", listError)
	}
}

func TestListSources_retourneErrAcquisitionInvalidePourUnYamlCasse(t *testing.T) {
	fixture := newAcquisitionFixture(t)
	writeFixtureFile(t, filepath.Join(fixture.confDir, "acquis.yaml"), "source: [unclosed\n")

	_, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if !errors.Is(listError, ErrAcquisitionInvalid) {
		t.Fatalf("error = %v, want ErrAcquisitionInvalid", listError)
	}
}

func TestListSources_retourneUneListeVideSansAcquisition(t *testing.T) {
	fixture := newAcquisitionFixture(t)

	listing, listError := ListSources(fixture.confDir, fixture.rootsDir)

	if listError != nil || len(listing.Sources) != 0 {
		t.Fatalf("got %v, %v", listing, listError)
	}
}
