package engines

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/sidecarauth"
)

const (
	sidecarURL = "https://sidecar.example.com:8443"
	// The operator may paste the pin in upper case: it must be stored in the
	// lower-case form the schema CHECK and the pinned transport compare.
	firstSidecarPinUpperCase = "AB12CD34AB12CD34AB12CD34AB12CD34AB12CD34AB12CD34AB12CD34AB12CD34"
	firstSidecarPin          = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"
	renewedSidecarPin        = "0f0e0d0c0b0a09080706050403020100f0e0d0c0b0a090807060504030201000"
)

var (
	signingKeyIDPattern  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	publicKeyHexPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sidecarColumnsSQLSet = `num_nonnulls(engine_sidecar_url, engine_sidecar_spki_sha256,
		engine_sidecar_signing_key_kid, engine_sidecar_signing_public_key,
		engine_sidecar_signing_key_sealed, engine_sidecar_signing_key_key_id,
		engine_sidecar_next_signing_key_kid, engine_sidecar_next_signing_public_key,
		engine_sidecar_next_signing_key_sealed, engine_sidecar_next_signing_key_key_id)`
)

func mustConfigureSidecar(testContext *testing.T, fixture testFixture, engineName, pin string) Engine {
	testContext.Helper()
	configuredEngine, configureError := fixture.repository.ConfigureSidecar(context.Background(), engineName,
		SidecarInput{URL: sidecarURL, SPKISHA256: pin})
	if configureError != nil {
		testContext.Fatalf("configure sidecar: %v", configureError)
	}
	if configuredEngine.Sidecar == nil {
		testContext.Fatal("a configured engine must expose its sidecar")
	}
	return configuredEngine
}

func mustOpenSidecarKeys(testContext *testing.T, fixture testFixture, engineID int64) (sidecarauth.SigningKey, *sidecarauth.SigningKey) {
	testContext.Helper()
	currentKey, nextKey, openError := fixture.repository.sidecarSigningKeys(context.Background(), engineID)
	if openError != nil {
		testContext.Fatalf("open sidecar signing keys: %v", openError)
	}
	return currentKey, nextKey
}

func countSetSidecarColumns(testContext *testing.T, fixture testFixture, engineID int64) int {
	testContext.Helper()
	var setColumnCount int
	if scanError := fixture.database.NewRaw(`SELECT `+sidecarColumnsSQLSet+` FROM engine WHERE engine_id = ?`, engineID).
		Scan(context.Background(), &setColumnCount); scanError != nil {
		testContext.Fatalf("count sidecar columns: %v", scanError)
	}
	return setColumnCount
}

func TestConfigureSidecarGeneratesAKeyAndPinsTheCertificate(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))

	configuredEngine := mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPinUpperCase)

	configuredSidecar := configuredEngine.Sidecar
	if configuredSidecar.URL != sidecarURL || configuredSidecar.SPKISHA256 != firstSidecarPin {
		testContext.Errorf("expected the URL and the lower-case pin stored, got %+v", configuredSidecar)
	}
	if !signingKeyIDPattern.MatchString(configuredSidecar.KeyID) || !publicKeyHexPattern.MatchString(configuredSidecar.PublicKeyHex) {
		testContext.Errorf("expected a 32 hex kid and a 64 hex public key, got %q %q", configuredSidecar.KeyID, configuredSidecar.PublicKeyHex)
	}
	if configuredSidecar.NextKeyID != "" || configuredSidecar.NextPublicKeyHex != "" {
		testContext.Errorf("a first enrolment must not stage a next key, got %+v", configuredSidecar)
	}

	currentKey, nextKey := mustOpenSidecarKeys(testContext, fixture, createdEngine.ID)
	if currentKey.KeyID != configuredSidecar.KeyID || currentKey.PublicKeyHex() != configuredSidecar.PublicKeyHex || nextKey != nil {
		testContext.Errorf("the sealed key must open to the advertised key, got %v next %v", currentKey, nextKey)
	}
	secretHex := hex.EncodeToString(currentKey.SecretBytes())

	var sealedSecret []byte
	var wholeRow string
	if scanError := fixture.database.QueryRowContext(context.Background(),
		`SELECT engine_sidecar_signing_key_sealed, engine::text FROM engine WHERE engine_id = ?`, createdEngine.ID).
		Scan(&sealedSecret, &wholeRow); scanError != nil {
		testContext.Fatalf("load sealed key: %v", scanError)
	}
	if len(sealedSecret) == 0 || bytes.Contains(sealedSecret, currentKey.SecretBytes()) || strings.Contains(wholeRow, secretHex) {
		testContext.Error("the stored row must hold the secret key only in sealed form")
	}

	listedEngine, getError := fixture.repository.Get(context.Background(), "edge-1")
	if getError != nil {
		testContext.Fatalf("get: %v", getError)
	}
	encodedEngine, marshalError := json.Marshal(listedEngine)
	if marshalError != nil {
		testContext.Fatalf("marshal engine: %v", marshalError)
	}
	formattedEngine := fmt.Sprintf("%+v %#v", listedEngine, listedEngine.Sidecar)
	if strings.Contains(string(encodedEngine), secretHex) || strings.Contains(formattedEngine, secretHex) {
		testContext.Error("the engine must never carry the secret signing key")
	}
}

func TestConfigureSidecarRepinsWithoutChangingTheKey(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	enrolledEngine := mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)

	// The host is case-insensitive: the same destination re-pins only.
	repinnedEngine, repinError := fixture.repository.ConfigureSidecar(context.Background(), "edge-1",
		SidecarInput{URL: "https://SIDECAR.example.com:8443", SPKISHA256: renewedSidecarPin})

	if repinError != nil {
		testContext.Fatalf("repin: %v", repinError)
	}
	if repinnedEngine.Sidecar.KeyID != enrolledEngine.Sidecar.KeyID || repinnedEngine.Sidecar.PublicKeyHex != enrolledEngine.Sidecar.PublicKeyHex {
		testContext.Errorf("a re-pin must keep the signing key, got %+v then %+v", enrolledEngine.Sidecar, repinnedEngine.Sidecar)
	}
	if repinnedEngine.Sidecar.SPKISHA256 != renewedSidecarPin || repinnedEngine.Sidecar.URL != sidecarURL {
		testContext.Errorf("a re-pin must store the new pin and keep the URL, got %+v", repinnedEngine.Sidecar)
	}
	mustOpenSidecarKeys(testContext, fixture, repinnedEngine.ID)
}

func TestConfigureSidecarRefusesAnotherURLAndTheLocalEngine(testContext *testing.T) {
	fixture := newFixture(testContext)
	ctx := context.Background()
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	mustCreate(testContext, fixture, remoteInput("edge-2", "https://two.example.com"))
	enrolledEngine := mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)
	if _, ensureError := fixture.repository.EnsureLocal(ctx, "http://127.0.0.1:8080", "dashboard"); ensureError != nil {
		testContext.Fatalf("ensure local: %v", ensureError)
	}

	_, otherURLError := fixture.repository.ConfigureSidecar(ctx, "edge-1",
		SidecarInput{URL: "https://other-sidecar.example.com:8443", SPKISHA256: renewedSidecarPin})
	if !errors.Is(otherURLError, ErrSidecarURLChange) {
		testContext.Errorf("another URL while configured must be refused, got %v", otherURLError)
	}
	unchangedEngine, getError := fixture.repository.Get(ctx, "edge-1")
	if getError != nil || *unchangedEngine.Sidecar != *enrolledEngine.Sidecar {
		testContext.Errorf("a refused change must leave the sidecar untouched, got %+v %v", unchangedEngine.Sidecar, getError)
	}

	_, localError := fixture.repository.ConfigureSidecar(ctx, ReservedLocalName, SidecarInput{URL: sidecarURL, SPKISHA256: firstSidecarPin})
	if !errors.Is(localError, ErrLocalReadOnly) {
		testContext.Errorf("the local engine must refuse a sidecar, got %v", localError)
	}
	_, unknownError := fixture.repository.ConfigureSidecar(ctx, "missing", SidecarInput{URL: sidecarURL, SPKISHA256: firstSidecarPin})
	if !errors.Is(unknownError, ErrEngineNotFound) {
		testContext.Errorf("an unknown engine must be reported, got %v", unknownError)
	}

	invalidInputs := map[string]SidecarInput{
		"plain http":     {URL: "http://sidecar.example.com:8443", SPKISHA256: firstSidecarPin},
		"path":           {URL: "https://sidecar.example.com:8443/base", SPKISHA256: firstSidecarPin},
		"trailing slash": {URL: "https://sidecar.example.com:8443/", SPKISHA256: firstSidecarPin},
		"query":          {URL: "https://sidecar.example.com:8443?next=1", SPKISHA256: firstSidecarPin},
		"fragment":       {URL: "https://sidecar.example.com:8443#top", SPKISHA256: firstSidecarPin},
		"userinfo":       {URL: "https://alice:secret@sidecar.example.com:8443", SPKISHA256: firstSidecarPin},
		"short pin":      {URL: sidecarURL, SPKISHA256: firstSidecarPin[:62]},
		"non hex pin":    {URL: sidecarURL, SPKISHA256: strings.Repeat("zz", 32)},
		"empty pin":      {URL: sidecarURL},
	}
	for caseName, invalidInput := range invalidInputs {
		_, invalidError := fixture.repository.ConfigureSidecar(ctx, "edge-2", invalidInput)
		if !errors.Is(invalidError, ErrInvalidEngine) {
			testContext.Errorf("%s: expected ErrInvalidEngine, got %v", caseName, invalidError)
		}
		if invalidError != nil && strings.Contains(invalidError.Error(), "secret") {
			testContext.Errorf("%s: the error must not echo the userinfo: %v", caseName, invalidError)
		}
	}
	untouchedEngine, untouchedError := fixture.repository.Get(ctx, "edge-2")
	if untouchedError != nil || untouchedEngine.Sidecar != nil {
		testContext.Errorf("refused inputs must not configure a sidecar, got %+v %v", untouchedEngine.Sidecar, untouchedError)
	}
}

func TestPromoteSidecarKeyReplacesCurrentByNext(testContext *testing.T) {
	fixture := newFixture(testContext)
	ctx := context.Background()
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	mustCreate(testContext, fixture, remoteInput("edge-2", "https://two.example.com"))
	enrolledEngine := mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)

	firstStagedEngine, firstStageError := fixture.repository.StageSidecarKey(ctx, "edge-1")
	if firstStageError != nil || firstStagedEngine.Sidecar.NextKeyID == "" {
		testContext.Fatalf("stage: %+v %v", firstStagedEngine.Sidecar, firstStageError)
	}
	stagedEngine, secondStageError := fixture.repository.StageSidecarKey(ctx, "edge-1")
	if secondStageError != nil {
		testContext.Fatalf("stage again: %v", secondStageError)
	}
	stagedSidecar := stagedEngine.Sidecar
	if stagedSidecar.NextKeyID == firstStagedEngine.Sidecar.NextKeyID || !publicKeyHexPattern.MatchString(stagedSidecar.NextPublicKeyHex) {
		testContext.Errorf("a second stage must replace the staged key, got %+v", stagedSidecar)
	}
	if stagedSidecar.KeyID != enrolledEngine.Sidecar.KeyID {
		testContext.Errorf("staging must keep the current key, got %+v", stagedSidecar)
	}
	stagedCurrentKey, stagedNextKey := mustOpenSidecarKeys(testContext, fixture, createdEngine.ID)
	if stagedCurrentKey.KeyID != stagedSidecar.KeyID || stagedNextKey == nil || stagedNextKey.KeyID != stagedSidecar.NextKeyID {
		testContext.Errorf("both keys must open, got %v and %v", stagedCurrentKey, stagedNextKey)
	}

	promotedEngine, promoteError := fixture.repository.PromoteSidecarKey(ctx, "edge-1", stagedSidecar.NextKeyID)
	if promoteError != nil {
		testContext.Fatalf("promote: %v", promoteError)
	}
	promotedSidecar := promotedEngine.Sidecar
	if promotedSidecar.KeyID != stagedSidecar.NextKeyID || promotedSidecar.PublicKeyHex != stagedSidecar.NextPublicKeyHex {
		testContext.Errorf("promotion must make the staged key current, got %+v", promotedSidecar)
	}
	if promotedSidecar.NextKeyID != "" || promotedSidecar.NextPublicKeyHex != "" {
		testContext.Errorf("promotion must clear the staged key, got %+v", promotedSidecar)
	}
	promotedCurrentKey, promotedNextKey := mustOpenSidecarKeys(testContext, fixture, createdEngine.ID)
	if promotedCurrentKey.KeyID != stagedNextKey.KeyID || !bytes.Equal(promotedCurrentKey.SecretBytes(), stagedNextKey.SecretBytes()) || promotedNextKey != nil {
		testContext.Errorf("the promoted key must open under its own kid, got %v next %v", promotedCurrentKey, promotedNextKey)
	}

	if _, secondPromoteError := fixture.repository.PromoteSidecarKey(ctx, "edge-1", stagedSidecar.NextKeyID); !errors.Is(secondPromoteError, ErrNoNextSidecarKey) {
		testContext.Errorf("promoting without a staged key must be refused, got %v", secondPromoteError)
	}
	if _, stageWithoutSidecarError := fixture.repository.StageSidecarKey(ctx, "edge-2"); !errors.Is(stageWithoutSidecarError, ErrEngineHasNoSidecar) {
		testContext.Errorf("staging without a sidecar must be refused, got %v", stageWithoutSidecarError)
	}
	if _, promoteWithoutSidecarError := fixture.repository.PromoteSidecarKey(ctx, "edge-2", stagedSidecar.NextKeyID); !errors.Is(promoteWithoutSidecarError, ErrEngineHasNoSidecar) {
		testContext.Errorf("promoting without a sidecar must be refused, got %v", promoteWithoutSidecarError)
	}
}

func TestSidecarKeyBoundToItsDestination(testContext *testing.T) {
	fixture := newFixture(testContext)
	ctx := context.Background()
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)
	if _, stageError := fixture.repository.StageSidecarKey(ctx, "edge-1"); stageError != nil {
		testContext.Fatalf("stage: %v", stageError)
	}
	currentKey, _ := mustOpenSidecarKeys(testContext, fixture, createdEngine.ID)
	secretHex := hex.EncodeToString(currentKey.SecretBytes())

	// Someone with write access to the database points the sidecar elsewhere:
	// the sealed keys are bound to the destination and must stop opening.
	if _, redirectError := fixture.database.ExecContext(ctx,
		`UPDATE engine SET engine_sidecar_url = 'https://attacker.example.com:8443' WHERE engine_id = ?`, createdEngine.ID); redirectError != nil {
		testContext.Fatalf("redirect: %v", redirectError)
	}
	_, _, redirectedError := fixture.repository.sidecarSigningKeys(ctx, createdEngine.ID)
	if !errors.Is(redirectedError, secrets.ErrDecrypt) {
		testContext.Errorf("a redirected sidecar must not open its key, got %v", redirectedError)
	}
	if redirectedError != nil && strings.Contains(redirectedError.Error(), secretHex) {
		testContext.Error("the error must not carry the secret key")
	}

	// Swapping the kid columns must fail as well: the kid is part of the
	// associated data, so a key cannot be presented under another identifier.
	if _, restoreError := fixture.database.ExecContext(ctx,
		`UPDATE engine SET engine_sidecar_url = ?,
		 engine_sidecar_signing_key_kid = engine_sidecar_next_signing_key_kid,
		 engine_sidecar_next_signing_key_kid = engine_sidecar_signing_key_kid WHERE engine_id = ?`, sidecarURL, createdEngine.ID); restoreError != nil {
		testContext.Fatalf("swap kids: %v", restoreError)
	}
	_, _, swappedError := fixture.repository.sidecarSigningKeys(ctx, createdEngine.ID)
	if !errors.Is(swappedError, secrets.ErrDecrypt) {
		testContext.Errorf("a key under another kid must not open, got %v", swappedError)
	}
}

func TestRemoveSidecarClearsEverySidecarColumn(testContext *testing.T) {
	fixture := newFixture(testContext)
	ctx := context.Background()
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)
	if _, stageError := fixture.repository.StageSidecarKey(ctx, "edge-1"); stageError != nil {
		testContext.Fatalf("stage: %v", stageError)
	}
	if setColumnCount := countSetSidecarColumns(testContext, fixture, createdEngine.ID); setColumnCount != 10 {
		testContext.Fatalf("expected the ten sidecar columns set, got %d", setColumnCount)
	}

	if removeError := fixture.repository.RemoveSidecar(ctx, "edge-1"); removeError != nil {
		testContext.Fatalf("remove: %v", removeError)
	}

	if setColumnCount := countSetSidecarColumns(testContext, fixture, createdEngine.ID); setColumnCount != 0 {
		testContext.Errorf("removal must clear every sidecar column, %d left", setColumnCount)
	}
	removedEngine, getError := fixture.repository.Get(ctx, "edge-1")
	if getError != nil || removedEngine.Sidecar != nil {
		testContext.Errorf("a removed sidecar must not be exposed, got %+v %v", removedEngine.Sidecar, getError)
	}
	if _, _, keysError := fixture.repository.sidecarSigningKeys(ctx, createdEngine.ID); !errors.Is(keysError, ErrEngineHasNoSidecar) {
		testContext.Errorf("no key may be returned after removal, got %v", keysError)
	}
	if secondRemoveError := fixture.repository.RemoveSidecar(ctx, "edge-1"); !errors.Is(secondRemoveError, ErrEngineHasNoSidecar) {
		testContext.Errorf("removing twice must report the missing sidecar, got %v", secondRemoveError)
	}
	reconfiguredEngine := mustConfigureSidecar(testContext, fixture, "edge-1", renewedSidecarPin)
	if reconfiguredEngine.Sidecar.SPKISHA256 != renewedSidecarPin {
		testContext.Errorf("a removed sidecar can be enrolled again, got %+v", reconfiguredEngine.Sidecar)
	}
}

func TestDeleteClearsTheSidecarSigningKeys(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)
	// Holding the purge mutex keeps the marked row in place while it is read.
	fixture.repository.purgeMutex.Lock()

	deleteError := fixture.repository.Delete(context.Background(), "edge-1")
	markedRowCount := countRows(testContext, fixture, `SELECT count(*) FROM engine WHERE engine_id = ? AND engine_deleting_at IS NOT NULL`, createdEngine.ID)
	remainingSidecarColumns := countSetSidecarColumns(testContext, fixture, createdEngine.ID)
	fixture.repository.purgeMutex.Unlock()
	fixture.repository.WaitPurges()

	if deleteError != nil || markedRowCount != 1 {
		testContext.Fatalf("delete: %v, marked rows: %d", deleteError, markedRowCount)
	}
	if remainingSidecarColumns != 0 {
		testContext.Errorf("a deleted engine must not keep its sidecar key, %d columns left", remainingSidecarColumns)
	}
}

// The key a promotion makes current must be the one the sidecar accepted: a
// stage that lands between the next-key ping and the promotion replaces the
// staged key, so the promotion is refused and nothing changes.
func TestPromoteSidecarKeyRefusesAKeyRestagedAfterThePing(testContext *testing.T) {
	fixture := newFixture(testContext)
	ctx := context.Background()
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	enrolledEngine := mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)
	pingedEngine, firstStageError := fixture.repository.StageSidecarKey(ctx, "edge-1")
	if firstStageError != nil {
		testContext.Fatalf("stage: %v", firstStageError)
	}
	restagedEngine, secondStageError := fixture.repository.StageSidecarKey(ctx, "edge-1")
	if secondStageError != nil {
		testContext.Fatalf("restage: %v", secondStageError)
	}

	_, promoteError := fixture.repository.PromoteSidecarKey(ctx, "edge-1", pingedEngine.Sidecar.NextKeyID)

	if !errors.Is(promoteError, ErrNextSidecarKeyChanged) {
		testContext.Fatalf("expected ErrNextSidecarKeyChanged, got %v", promoteError)
	}
	unchangedEngine, getError := fixture.repository.Get(ctx, "edge-1")
	if getError != nil {
		testContext.Fatalf("get: %v", getError)
	}
	if unchangedEngine.Sidecar.KeyID != enrolledEngine.Sidecar.KeyID || unchangedEngine.Sidecar.NextKeyID != restagedEngine.Sidecar.NextKeyID {
		testContext.Errorf("a refused promotion must leave both keys in place, got %+v", unchangedEngine.Sidecar)
	}
}
