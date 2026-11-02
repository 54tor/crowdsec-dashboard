package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

// sampleColumn is a test-only registry entry: a dedicated table lets the
// rotation tests control every row without depending on the account or engine
// schemas. The filter mirrors the credential kind filter of the real registry.
var sampleColumn = EncryptedColumn{
	Table:                 "rotation_sample",
	IDColumn:              "rotation_sample_id",
	CiphertextColumn:      "rotation_sample_sealed",
	KeyIDColumn:           "rotation_sample_key_id",
	Filter:                "rotation_sample_kind = 'secret'",
	AssociatedDataColumns: []string{"rotation_sample_owner_id"},
	AssociatedData:        labelledAssociatedData("sample"),
}

const testBatchSize = 2

type rotationFixture struct {
	database        *bun.DB
	retiredKeyring  *Keyring
	rotatingKeyring *Keyring
}

// newRotationFixture builds the state an operator has after the documented
// procedure's first step: rows sealed under the old key, then a restart with a
// new current key and the old one listed as retired.
func newRotationFixture(testContext *testing.T) rotationFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	_, createError := database.ExecContext(context.Background(), `CREATE TABLE rotation_sample (
		rotation_sample_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
		rotation_sample_owner_id bigint NOT NULL,
		rotation_sample_kind text NOT NULL,
		rotation_sample_sealed bytea,
		rotation_sample_key_id text)`)
	if createError != nil {
		testContext.Fatalf("create sample table: %v", createError)
	}
	rotatingKeyring, loadError := LoadKeyringWithRetired(encodedKeyFile(testContext, 2), []string{encodedKeyFile(testContext, 1)})
	if loadError != nil {
		testContext.Fatalf("load rotating keyring: %v", loadError)
	}
	return rotationFixture{database: database, retiredKeyring: newTestKeyring(testContext, 1), rotatingKeyring: rotatingKeyring}
}

func sampleAssociatedData(ownerID int64) []byte {
	return []byte("sample:" + strconv.FormatInt(ownerID, 10))
}

func (fixture rotationFixture) insertSample(testContext *testing.T, keyring *Keyring, ownerID int64, kind, plaintext string) int64 {
	testContext.Helper()
	ciphertext, keyID, sealError := keyring.Seal([]byte(plaintext), sampleAssociatedData(ownerID))
	if sealError != nil {
		testContext.Fatalf("seal sample: %v", sealError)
	}
	var insertedID int64
	insertError := fixture.database.QueryRowContext(context.Background(),
		`INSERT INTO rotation_sample (rotation_sample_owner_id, rotation_sample_kind, rotation_sample_sealed, rotation_sample_key_id)
		 VALUES (?, ?, ?, ?) RETURNING rotation_sample_id`, ownerID, kind, ciphertext, keyID).Scan(&insertedID)
	if insertError != nil {
		testContext.Fatalf("insert sample: %v", insertError)
	}
	return insertedID
}

// insertOldSamples seeds rowCount rows sealed under the retired key, each with
// its own owner so that the associated data differs per row.
func (fixture rotationFixture) insertOldSamples(testContext *testing.T, rowCount int) map[int64]string {
	testContext.Helper()
	plaintextByID := map[int64]string{}
	for ownerID := int64(1); ownerID <= int64(rowCount); ownerID++ {
		plaintext := fmt.Sprintf("secret-of-owner-%d", ownerID)
		plaintextByID[fixture.insertSample(testContext, fixture.retiredKeyring, ownerID, "secret", plaintext)] = plaintext
	}
	return plaintextByID
}

type storedSample struct {
	ownerID    int64
	ciphertext []byte
	keyID      string
}

func (fixture rotationFixture) loadSample(testContext *testing.T, sampleID int64) storedSample {
	testContext.Helper()
	var loaded storedSample
	scanError := fixture.database.QueryRowContext(context.Background(),
		`SELECT rotation_sample_owner_id, rotation_sample_sealed, rotation_sample_key_id FROM rotation_sample WHERE rotation_sample_id = ?`,
		sampleID).Scan(&loaded.ownerID, &loaded.ciphertext, &loaded.keyID)
	if scanError != nil {
		testContext.Fatalf("load sample %d: %v", sampleID, scanError)
	}
	return loaded
}

func (fixture rotationFixture) openSample(testContext *testing.T, sampleID int64) (string, string) {
	testContext.Helper()
	loaded := fixture.loadSample(testContext, sampleID)
	plaintext, openError := fixture.rotatingKeyring.Open(loaded.ciphertext, loaded.keyID, sampleAssociatedData(loaded.ownerID))
	if openError != nil {
		testContext.Fatalf("open sample %d: %v", sampleID, openError)
	}
	return string(plaintext), loaded.keyID
}

func (fixture rotationFixture) rotate(testContext *testing.T, dryRun bool) RotationReport {
	testContext.Helper()
	report, rotateError := rotateColumns(context.Background(), fixture.database, fixture.rotatingKeyring, []EncryptedColumn{sampleColumn}, dryRun, testBatchSize)
	if rotateError != nil {
		testContext.Fatalf("rotate: %v", rotateError)
	}
	return report
}

func (fixture rotationFixture) keyIDCounts(testContext *testing.T) map[string]int64 {
	testContext.Helper()
	counts, countError := keyIDsInUse(context.Background(), fixture.database, []EncryptedColumn{sampleColumn})
	if countError != nil {
		testContext.Fatalf("count key ids: %v", countError)
	}
	return counts
}

func TestDryRunCountsWithoutWriting(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	plaintextByID := fixture.insertOldSamples(testContext, 3)
	ciphertextBefore := map[int64][]byte{}
	for sampleID := range plaintextByID {
		ciphertextBefore[sampleID] = fixture.loadSample(testContext, sampleID).ciphertext
	}

	report := fixture.rotate(testContext, true)

	if len(report.Columns) != 1 || report.Columns[0].KeyIDCounts[fixture.retiredKeyring.CurrentKeyID()] != 3 {
		testContext.Fatalf("dry run must count the three old rows, got %+v", report)
	}
	if report.Columns[0].Rewritten != 0 || report.Rewritten() != 0 {
		testContext.Errorf("dry run must not rewrite, got %+v", report.Columns[0])
	}
	for sampleID, ciphertext := range ciphertextBefore {
		if string(fixture.loadSample(testContext, sampleID).ciphertext) != string(ciphertext) {
			testContext.Errorf("dry run changed sample %d", sampleID)
		}
	}
}

func TestRotateReencryptsEveryRowUnderCurrentKey(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	plaintextByID := fixture.insertOldSamples(testContext, 5)
	fixture.insertSample(testContext, fixture.rotatingKeyring, 99, "secret", "already-current")

	report := fixture.rotate(testContext, false)

	if report.Rewritten() != 5 {
		testContext.Errorf("expected five rewritten rows, got %d", report.Rewritten())
	}
	for sampleID, expectedPlaintext := range plaintextByID {
		obtainedPlaintext, obtainedKeyID := fixture.openSample(testContext, sampleID)
		if obtainedPlaintext != expectedPlaintext || obtainedKeyID != fixture.rotatingKeyring.CurrentKeyID() {
			testContext.Errorf("sample %d: got %q under %q", sampleID, obtainedPlaintext, obtainedKeyID)
		}
	}
	counts := fixture.keyIDCounts(testContext)
	if len(counts) != 1 || counts[fixture.rotatingKeyring.CurrentKeyID()] != 6 {
		testContext.Errorf("every row must use the current key, got %v", counts)
	}
}

func TestRotateSkipsRowsOutsideTheFilter(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	ignoredSampleID := fixture.insertSample(testContext, fixture.retiredKeyring, 1, "other", "not-registered")

	fixture.rotate(testContext, false)

	if fixture.loadSample(testContext, ignoredSampleID).keyID != fixture.retiredKeyring.CurrentKeyID() {
		testContext.Error("a row outside the column filter must be left untouched")
	}
}

func TestRotatedCiphertextMovedToOtherRowStillFails(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	firstSampleID := fixture.insertSample(testContext, fixture.retiredKeyring, 1, "secret", "first-secret")
	secondSampleID := fixture.insertSample(testContext, fixture.retiredKeyring, 2, "secret", "second-secret")
	fixture.rotate(testContext, false)

	firstSample := fixture.loadSample(testContext, firstSampleID)
	_, moveError := fixture.database.ExecContext(context.Background(),
		`UPDATE rotation_sample SET rotation_sample_sealed = ?, rotation_sample_key_id = ? WHERE rotation_sample_id = ?`,
		firstSample.ciphertext, firstSample.keyID, secondSampleID)
	if moveError != nil {
		testContext.Fatalf("move ciphertext: %v", moveError)
	}
	movedSample := fixture.loadSample(testContext, secondSampleID)
	_, openError := fixture.rotatingKeyring.Open(movedSample.ciphertext, movedSample.keyID, sampleAssociatedData(movedSample.ownerID))

	if !errors.Is(openError, ErrDecrypt) {
		testContext.Errorf("a rotated ciphertext moved to another row must fail with ErrDecrypt, got %v", openError)
	}
}

func TestRotateReportsKeyIDsPerColumn(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	fixture.insertOldSamples(testContext, 2)
	fixture.insertSample(testContext, fixture.rotatingKeyring, 50, "secret", "current")

	report := fixture.rotate(testContext, false)

	if len(report.Columns) != 1 {
		testContext.Fatalf("expected one column, got %d", len(report.Columns))
	}
	columnReport := report.Columns[0]
	if columnReport.Column != "rotation_sample.rotation_sample_sealed" {
		testContext.Errorf("unexpected column name %q", columnReport.Column)
	}
	expectedCounts := map[string]int64{fixture.retiredKeyring.CurrentKeyID(): 2, fixture.rotatingKeyring.CurrentKeyID(): 1}
	if fmt.Sprint(columnReport.KeyIDCounts) != fmt.Sprint(expectedCounts) {
		testContext.Errorf("expected counts before rotation %v, got %v", expectedCounts, columnReport.KeyIDCounts)
	}
	if columnReport.Rewritten != 2 || columnReport.SkippedConcurrent != 0 {
		testContext.Errorf("expected two rewritten and none skipped, got %+v", columnReport)
	}
}

func TestRotateInterruptedMidwayStaysReadableAndResumes(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	plaintextByID := fixture.insertOldSamples(testContext, 5)

	// A rotation that stops after its first batch leaves exactly the state an
	// interrupted command leaves: the first batch committed, the rest untouched.
	firstBatch, selectError := selectBatch(context.Background(), fixture.database, sampleColumn, fixture.rotatingKeyring.CurrentKeyID(), 0, testBatchSize)
	if selectError != nil {
		testContext.Fatalf("select batch: %v", selectError)
	}
	if _, rewriteError := rewriteBatch(context.Background(), fixture.database, fixture.rotatingKeyring, sampleColumn, firstBatch); rewriteError != nil {
		testContext.Fatalf("rewrite batch: %v", rewriteError)
	}
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	_, cancelledError := rotateColumns(cancelledContext, fixture.database, fixture.rotatingKeyring, []EncryptedColumn{sampleColumn}, false, testBatchSize)
	if cancelledError == nil {
		testContext.Error("a cancelled rotation must report its interruption")
	}

	mixedCounts := fixture.keyIDCounts(testContext)
	if mixedCounts[fixture.rotatingKeyring.CurrentKeyID()] != 2 || mixedCounts[fixture.retiredKeyring.CurrentKeyID()] != 3 {
		testContext.Fatalf("expected mixed key ids 2/3, got %v", mixedCounts)
	}
	for sampleID, expectedPlaintext := range plaintextByID {
		if obtainedPlaintext, _ := fixture.openSample(testContext, sampleID); obtainedPlaintext != expectedPlaintext {
			testContext.Errorf("sample %d unreadable after interruption: %q", sampleID, obtainedPlaintext)
		}
	}

	fixture.rotate(testContext, false)
	verification := fixture.rotate(testContext, true)
	if pending := verification.Columns[0].KeyIDCounts[fixture.retiredKeyring.CurrentKeyID()]; pending != 0 {
		testContext.Errorf("the second run must finish the rotation, %d rows remain", pending)
	}
}

func TestRotateNeverOverwritesConcurrentlyUpdatedSecret(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	sampleID := fixture.insertSample(testContext, fixture.retiredKeyring, 1, "secret", "before-update")
	staleBatch, selectError := selectBatch(context.Background(), fixture.database, sampleColumn, fixture.rotatingKeyring.CurrentKeyID(), 0, testBatchSize)
	if selectError != nil || len(staleBatch) != 1 {
		testContext.Fatalf("select batch: %d rows, %v", len(staleBatch), selectError)
	}

	// The server rewrites the secret between the rotation's read and its update.
	freshCiphertext, freshKeyID, _ := fixture.retiredKeyring.Seal([]byte("written-by-server"), sampleAssociatedData(1))
	_, updateError := fixture.database.ExecContext(context.Background(),
		`UPDATE rotation_sample SET rotation_sample_sealed = ?, rotation_sample_key_id = ? WHERE rotation_sample_id = ?`,
		freshCiphertext, freshKeyID, sampleID)
	if updateError != nil {
		testContext.Fatalf("concurrent update: %v", updateError)
	}
	outcome, rewriteError := rewriteBatch(context.Background(), fixture.database, fixture.rotatingKeyring, sampleColumn, staleBatch)
	if rewriteError != nil {
		testContext.Fatalf("rewrite batch: %v", rewriteError)
	}

	if outcome.rewritten != 0 || outcome.skippedConcurrent != 1 {
		testContext.Errorf("expected the row to be skipped, got %+v", outcome)
	}
	if obtainedPlaintext, _ := fixture.openSample(testContext, sampleID); obtainedPlaintext != "written-by-server" {
		testContext.Errorf("the concurrent value must be kept, got %q", obtainedPlaintext)
	}
}

func TestCheckKeysAvailableRefusesMissingKeyID(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	fixture.insertOldSamples(testContext, 1)
	keyringWithoutRetired := newTestKeyring(testContext, 2)

	checkError := checkKeysAvailable(context.Background(), fixture.database, keyringWithoutRetired, []EncryptedColumn{sampleColumn})

	if !errors.Is(checkError, ErrMissingKeys) {
		testContext.Fatalf("expected ErrMissingKeys, got %v", checkError)
	}
	if !strings.Contains(checkError.Error(), fixture.retiredKeyring.CurrentKeyID()) {
		testContext.Errorf("the error must name the missing key id: %v", checkError)
	}
	if strings.Contains(checkError.Error(), base64.StdEncoding.EncodeToString(testKeyBytes(1))) {
		testContext.Error("the error must never contain key material")
	}
	if availableError := checkKeysAvailable(context.Background(), fixture.database, fixture.rotatingKeyring, []EncryptedColumn{sampleColumn}); availableError != nil {
		testContext.Errorf("a keyring holding every key id must pass, got %v", availableError)
	}
}

// TestRotateKeepsAssociatedDataPerColumn runs the real registry against real
// credential and engine rows, sealed the way secondfactor and engines seal them.
func TestRotateKeepsAssociatedDataPerColumn(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	ctx := context.Background()
	var firstAccountID, otherAccountID, engineID int64
	if scanError := fixture.database.QueryRowContext(ctx,
		`INSERT INTO account (account_name) VALUES ('alice') RETURNING account_id`).Scan(&firstAccountID); scanError != nil {
		testContext.Fatalf("insert account: %v", scanError)
	}
	if scanError := fixture.database.QueryRowContext(ctx,
		`INSERT INTO account (account_name) VALUES ('bob') RETURNING account_id`).Scan(&otherAccountID); scanError != nil {
		testContext.Fatalf("insert other account: %v", scanError)
	}
	totpAssociatedData := []byte("totp:" + strconv.FormatInt(firstAccountID, 10))
	totpCiphertext, totpKeyID, _ := fixture.retiredKeyring.Seal([]byte("totp-secret"), totpAssociatedData)
	if _, insertError := fixture.database.ExecContext(ctx,
		`INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id) VALUES (?, 'totp', ?, ?)`,
		firstAccountID, totpCiphertext, totpKeyID); insertError != nil {
		testContext.Fatalf("insert totp credential: %v", insertError)
	}
	if scanError := fixture.database.QueryRowContext(ctx,
		`INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id)
		 VALUES ('remote', 'https://lapi.example.com', 'machine', '\x00', 'placeholder') RETURNING engine_id`).Scan(&engineID); scanError != nil {
		testContext.Fatalf("insert engine: %v", scanError)
	}
	// The engine password is sealed in the legacy id-only form: the rotation
	// must reseal it under the destination-bound form.
	legacyPasswordAssociatedData := LegacyEngineMachinePasswordAssociatedData(engineID)
	passwordAssociatedData := EngineMachinePasswordAssociatedData(engineID, "https://lapi.example.com")
	passwordCiphertext, passwordKeyID, _ := fixture.retiredKeyring.Seal([]byte("machine-password"), legacyPasswordAssociatedData)
	if _, updateError := fixture.database.ExecContext(ctx,
		`UPDATE engine SET engine_machine_password_sealed = ?, engine_machine_password_key_id = ? WHERE engine_id = ?`,
		passwordCiphertext, passwordKeyID, engineID); updateError != nil {
		testContext.Fatalf("seal engine password: %v", updateError)
	}

	report, rotateError := Rotate(ctx, fixture.database, fixture.rotatingKeyring, false, 500)
	if rotateError != nil {
		testContext.Fatalf("rotate: %v", rotateError)
	}
	if report.Rewritten() != 2 || len(report.Columns) != len(EncryptedColumns) {
		testContext.Fatalf("expected two rewritten rows over every registered column, got %+v", report)
	}

	var rotatedTOTP storedSample
	if scanError := fixture.database.QueryRowContext(ctx,
		`SELECT credential_secret_ciphertext, credential_key_id FROM credential WHERE credential_account_id = ? AND credential_kind = 'totp'`,
		firstAccountID).Scan(&rotatedTOTP.ciphertext, &rotatedTOTP.keyID); scanError != nil {
		testContext.Fatalf("load totp: %v", scanError)
	}
	if plaintext, openError := fixture.rotatingKeyring.Open(rotatedTOTP.ciphertext, rotatedTOTP.keyID, totpAssociatedData); openError != nil || string(plaintext) != "totp-secret" {
		testContext.Errorf("rotated totp must open with its own account, got %q %v", plaintext, openError)
	}
	otherTOTPAssociatedData := []byte("totp:" + strconv.FormatInt(otherAccountID, 10))
	if _, openError := fixture.rotatingKeyring.Open(rotatedTOTP.ciphertext, rotatedTOTP.keyID, otherTOTPAssociatedData); !errors.Is(openError, ErrDecrypt) {
		testContext.Errorf("rotated totp must fail for another account, got %v", openError)
	}

	var rotatedPassword storedSample
	if scanError := fixture.database.QueryRowContext(ctx,
		`SELECT engine_machine_password_sealed, engine_machine_password_key_id FROM engine WHERE engine_id = ?`,
		engineID).Scan(&rotatedPassword.ciphertext, &rotatedPassword.keyID); scanError != nil {
		testContext.Fatalf("load engine password: %v", scanError)
	}
	if rotatedPassword.keyID != fixture.rotatingKeyring.CurrentKeyID() {
		testContext.Errorf("engine password must use the current key, got %q", rotatedPassword.keyID)
	}
	if plaintext, openError := fixture.rotatingKeyring.Open(rotatedPassword.ciphertext, rotatedPassword.keyID, passwordAssociatedData); openError != nil || string(plaintext) != "machine-password" {
		testContext.Errorf("rotated engine password must open with its own engine, got %q %v", plaintext, openError)
	}
	proxyAssociatedData := EngineProxyCredentialAssociatedData(engineID, "https://lapi.example.com", "socks5", "socks5://proxy.example.com:1080")
	if _, openError := fixture.rotatingKeyring.Open(rotatedPassword.ciphertext, rotatedPassword.keyID, proxyAssociatedData); !errors.Is(openError, ErrDecrypt) {
		testContext.Errorf("engine password must fail under another column's label, got %v", openError)
	}
}
