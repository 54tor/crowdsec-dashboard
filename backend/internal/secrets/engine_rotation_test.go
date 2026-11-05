package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/store/storetest"
)

const (
	engineLAPIURL   = "https://lapi.example.com/v1"
	engineProxyKind = "socks5"
	engineProxyURL  = "socks5://proxy.example.com:1080"
)

type sealedEngineSecrets struct {
	passwordCiphertext   []byte
	passwordKeyID        string
	credentialCiphertext []byte
	credentialKeyID      string
}

// insertProxiedEngine stores an engine whose machine password and proxy
// credential are sealed by sealingKeyring under the associated data chosen by
// the caller, so that a test can seed either the destination-bound form or the
// legacy id-only form written before the destination was bound.
func insertProxiedEngine(testContext *testing.T, fixture rotationFixture, sealingKeyring *Keyring, name string, passwordAssociatedData, credentialAssociatedData func(engineID int64) []byte) int64 {
	testContext.Helper()
	ctx := context.Background()
	var engineID int64
	if scanError := fixture.database.QueryRowContext(ctx,
		`INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id, engine_proxy_kind, engine_proxy_url)
		 VALUES (?, ?, 'machine', '\x00', 'placeholder', ?, ?) RETURNING engine_id`,
		name, engineLAPIURL, engineProxyKind, engineProxyURL).Scan(&engineID); scanError != nil {
		testContext.Fatalf("insert engine: %v", scanError)
	}
	passwordCiphertext, passwordKeyID, _ := sealingKeyring.Seal([]byte("machine-password-"+name), passwordAssociatedData(engineID))
	credentialPayload, _ := json.Marshal(map[string]string{"username": "proxy-user", "password": "proxy-password-" + name})
	credentialCiphertext, credentialKeyID, _ := sealingKeyring.Seal(credentialPayload, credentialAssociatedData(engineID))
	if _, updateError := fixture.database.ExecContext(ctx,
		`UPDATE engine SET engine_machine_password_sealed = ?, engine_machine_password_key_id = ?,
		 engine_proxy_credential_sealed = ?, engine_proxy_credential_key_id = ? WHERE engine_id = ?`,
		passwordCiphertext, passwordKeyID, credentialCiphertext, credentialKeyID, engineID); updateError != nil {
		testContext.Fatalf("seal engine secrets: %v", updateError)
	}
	return engineID
}

func destinationPasswordAssociatedData(engineID int64) []byte {
	return EngineMachinePasswordAssociatedData(engineID, engineLAPIURL)
}

func destinationCredentialAssociatedData(engineID int64) []byte {
	return EngineProxyCredentialAssociatedData(engineID, engineLAPIURL, engineProxyKind, engineProxyURL)
}

func loadEngineSecrets(testContext *testing.T, fixture rotationFixture, engineID int64) sealedEngineSecrets {
	testContext.Helper()
	var loaded sealedEngineSecrets
	if scanError := fixture.database.QueryRowContext(context.Background(),
		`SELECT engine_machine_password_sealed, engine_machine_password_key_id, engine_proxy_credential_sealed, engine_proxy_credential_key_id
		 FROM engine WHERE engine_id = ?`, engineID).Scan(
		&loaded.passwordCiphertext, &loaded.passwordKeyID, &loaded.credentialCiphertext, &loaded.credentialKeyID); scanError != nil {
		testContext.Fatalf("load engine secrets: %v", scanError)
	}
	return loaded
}

// requireDestinationBound checks that both secrets of the engine use the
// current key and open only under the destination-bound associated data.
func requireDestinationBound(testContext *testing.T, fixture rotationFixture, engineID int64, name string) {
	testContext.Helper()
	loaded := loadEngineSecrets(testContext, fixture, engineID)
	currentKeyID := fixture.rotatingKeyring.CurrentKeyID()
	if loaded.passwordKeyID != currentKeyID || loaded.credentialKeyID != currentKeyID {
		testContext.Errorf("%s: secrets must use the current key, got %q and %q", name, loaded.passwordKeyID, loaded.credentialKeyID)
	}
	password, passwordError := fixture.rotatingKeyring.Open(loaded.passwordCiphertext, loaded.passwordKeyID, destinationPasswordAssociatedData(engineID))
	if passwordError != nil || string(password) != "machine-password-"+name {
		testContext.Errorf("%s: password must open under the destination associated data, got %q %v", name, password, passwordError)
	}
	credential, credentialError := fixture.rotatingKeyring.Open(loaded.credentialCiphertext, loaded.credentialKeyID, destinationCredentialAssociatedData(engineID))
	if credentialError != nil || !bytes.Contains(credential, []byte("proxy-password-"+name)) {
		testContext.Errorf("%s: proxy credential must open under the destination associated data, got %v", name, credentialError)
	}
	if _, legacyError := fixture.rotatingKeyring.Open(loaded.passwordCiphertext, loaded.passwordKeyID, LegacyEngineMachinePasswordAssociatedData(engineID)); legacyError == nil {
		testContext.Errorf("%s: password must no longer open under the legacy associated data", name)
	}
	if _, legacyError := fixture.rotatingKeyring.Open(loaded.credentialCiphertext, loaded.credentialKeyID, LegacyEngineProxyCredentialAssociatedData(engineID)); legacyError == nil {
		testContext.Errorf("%s: proxy credential must no longer open under the legacy associated data", name)
	}
}

func TestRotateReproducesDestinationAssociatedData(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	engineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "remote",
		destinationPasswordAssociatedData, destinationCredentialAssociatedData)

	report, rotateError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, false, testBatchSize)

	if rotateError != nil {
		testContext.Fatalf("rotate: %v", rotateError)
	}
	if report.Rewritten() != 2 {
		testContext.Errorf("expected the password and the proxy credential rewritten, got %+v", report)
	}
	requireDestinationBound(testContext, fixture, engineID, "remote")
}

func TestLegacyAssociatedDataIsResealedOnRotation(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	// One engine is still under the retired key, the other was sealed under
	// the current key before the destination was bound: a key-id filter alone
	// would never select the second one.
	retiredEngineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "retired",
		LegacyEngineMachinePasswordAssociatedData, LegacyEngineProxyCredentialAssociatedData)
	currentEngineID := insertProxiedEngine(testContext, fixture, fixture.rotatingKeyring, "current",
		LegacyEngineMachinePasswordAssociatedData, LegacyEngineProxyCredentialAssociatedData)

	firstReport, rotateError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, false, testBatchSize)
	if rotateError != nil {
		testContext.Fatalf("rotate: %v", rotateError)
	}
	if firstReport.Rewritten() != 4 {
		testContext.Errorf("expected four legacy secrets resealed, got %+v", firstReport)
	}
	requireDestinationBound(testContext, fixture, retiredEngineID, "retired")
	requireDestinationBound(testContext, fixture, currentEngineID, "current")

	secondReport, secondError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, false, testBatchSize)
	if secondError != nil || secondReport.Rewritten() != 0 {
		testContext.Errorf("a second rotation must find nothing left in legacy form, got %+v %v", secondReport, secondError)
	}
}

func TestEngineAssociatedDataSeparatesItsParts(testContext *testing.T) {
	// The proxy URL and the destination both contain colons: moving text from
	// one part to the next must still change the associated data.
	firstAssociatedData := EngineProxyCredentialAssociatedData(1, "https://a.example.com", "http", "http://b.example.com:3128")
	shiftedAssociatedData := EngineProxyCredentialAssociatedData(1, "https://a.example.com", "http:", "//b.example.com:3128")
	if bytes.Equal(firstAssociatedData, shiftedAssociatedData) {
		testContext.Error("shifting text between parts must change the associated data")
	}
	pathOnlyChange := EngineMachinePasswordAssociatedData(1, "https://a.example.com/other-path")
	if !bytes.Equal(EngineMachinePasswordAssociatedData(1, "https://A.example.com:443"), pathOnlyChange) {
		testContext.Error("the machine password binds to the destination (scheme, host, port), not to the path")
	}
	if string(EngineMachinePasswordAssociatedData(7, "https://a.example.com")) != "engine.machine_password:7:https://a.example.com:443" {
		testContext.Errorf("unexpected machine password associated data %q", EngineMachinePasswordAssociatedData(7, "https://a.example.com"))
	}
}

// credentialColumnReports keeps the reports of the two engine columns sealed
// by insertProxiedEngine and checks that every other engine column (sidecar
// keys) holds no row in these tests, so it reports nothing unreadable.
func credentialColumnReports(testContext *testing.T, report RotationReport) []ColumnReport {
	testContext.Helper()
	credentialColumnNames := map[string]bool{
		"engine.engine_machine_password_sealed": true,
		"engine.engine_proxy_credential_sealed": true,
	}
	var credentialReports []ColumnReport
	for _, columnReport := range report.Columns {
		if credentialColumnNames[columnReport.Column] {
			credentialReports = append(credentialReports, columnReport)
			continue
		}
		if strings.HasPrefix(columnReport.Column, "engine.") && len(columnReport.UnreadableIDs) != 0 {
			testContext.Errorf("%s: expected no unreadable ids, got %v", columnReport.Column, columnReport.UnreadableIDs)
		}
	}
	if len(credentialReports) != len(credentialColumnNames) {
		testContext.Fatalf("expected %d credential column reports, got %d", len(credentialColumnNames), len(credentialReports))
	}
	return credentialReports
}

func TestRotateReportsUnreadableRowsAndContinues(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	ctx := context.Background()
	var accountID int64
	if scanError := fixture.database.QueryRowContext(ctx,
		`INSERT INTO account (account_name) VALUES ('alice') RETURNING account_id`).Scan(&accountID); scanError != nil {
		testContext.Fatalf("insert account: %v", scanError)
	}
	totpCiphertext, totpKeyID, _ := fixture.retiredKeyring.Seal([]byte("totp-secret"), []byte("totp:"+strconv.FormatInt(accountID, 10)))
	if _, insertError := fixture.database.ExecContext(ctx,
		`INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id) VALUES (?, 'totp', ?, ?)`,
		accountID, totpCiphertext, totpKeyID); insertError != nil {
		testContext.Fatalf("insert totp credential: %v", insertError)
	}
	tamperedEngineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "tampered",
		destinationPasswordAssociatedData, destinationCredentialAssociatedData)
	readableEngineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "readable",
		destinationPasswordAssociatedData, destinationCredentialAssociatedData)
	// The tampered engine was pointed elsewhere directly in the database: both
	// of its secrets no longer open, and the rotation must step over them.
	if _, tamperError := fixture.database.ExecContext(ctx,
		`UPDATE engine SET engine_lapi_url = 'https://attacker.example.com' WHERE engine_id = ?`, tamperedEngineID); tamperError != nil {
		testContext.Fatalf("tamper: %v", tamperError)
	}
	expectedUnreadable := []int64{tamperedEngineID}

	dryRunReport, dryRunError := Rotate(ctx, fixture.database, fixture.rotatingKeyring, true, testBatchSize)
	if !errors.Is(dryRunError, ErrUnreadableRows) {
		testContext.Errorf("the dry run must report the unreadable rows, got %v", dryRunError)
	}
	for _, columnReport := range credentialColumnReports(testContext, dryRunReport) {
		if fmt.Sprint(columnReport.UnreadableIDs) != fmt.Sprint(expectedUnreadable) {
			testContext.Errorf("dry run %s: expected unreadable %v, got %v", columnReport.Column, expectedUnreadable, columnReport.UnreadableIDs)
		}
	}
	if dryRunReport.Rewritten() != 0 {
		testContext.Errorf("a dry run must not rewrite, got %d", dryRunReport.Rewritten())
	}

	report, rotateError := Rotate(ctx, fixture.database, fixture.rotatingKeyring, false, testBatchSize)

	if !errors.Is(rotateError, ErrUnreadableRows) {
		testContext.Fatalf("expected ErrUnreadableRows, got %v", rotateError)
	}
	if !strings.Contains(rotateError.Error(), strconv.FormatInt(tamperedEngineID, 10)) || strings.Contains(rotateError.Error(), "machine-password") {
		testContext.Errorf("the error must list the row id and nothing secret: %v", rotateError)
	}
	if report.Rewritten() != 3 || len(report.Columns) != len(EncryptedColumns) {
		testContext.Errorf("expected the totp and both readable engine secrets rewritten over every column, got %+v", report)
	}
	for _, columnReport := range credentialColumnReports(testContext, report) {
		if fmt.Sprint(columnReport.UnreadableIDs) != fmt.Sprint(expectedUnreadable) {
			testContext.Errorf("%s: expected unreadable %v, got %v", columnReport.Column, expectedUnreadable, columnReport.UnreadableIDs)
		}
	}
	requireDestinationBound(testContext, fixture, readableEngineID, "readable")
	var totpKeyIDAfter string
	if scanError := fixture.database.QueryRowContext(ctx,
		`SELECT credential_key_id FROM credential WHERE credential_account_id = ?`, accountID).Scan(&totpKeyIDAfter); scanError != nil {
		testContext.Fatalf("load totp: %v", scanError)
	}
	if totpKeyIDAfter != fixture.rotatingKeyring.CurrentKeyID() {
		testContext.Errorf("the totp column must be rotated, got key id %q", totpKeyIDAfter)
	}
}

func TestRotateNeverBindsToADestinationChangedAfterTheRead(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	engineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "remote",
		LegacyEngineMachinePasswordAssociatedData, LegacyEngineProxyCredentialAssociatedData)
	passwordColumn := EncryptedColumns[1]
	staleBatch, selectError := selectBatch(context.Background(), fixture.database, passwordColumn, fixture.rotatingKeyring.CurrentKeyID(), 0, testBatchSize)
	if selectError != nil || len(staleBatch) != 1 {
		testContext.Fatalf("select batch: %d rows, %v", len(staleBatch), selectError)
	}

	// The destination changes between the read and the rewrite while the
	// ciphertext stays the same: only the pinned associated columns notice it.
	if _, redirectError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_lapi_url = 'https://attacker.example.com' WHERE engine_id = ?`, engineID); redirectError != nil {
		testContext.Fatalf("redirect: %v", redirectError)
	}
	outcome, rewriteError := rewriteBatch(context.Background(), fixture.database, fixture.rotatingKeyring, passwordColumn, staleBatch)

	if rewriteError != nil || outcome.rewritten != 0 || outcome.skippedConcurrent != 1 {
		testContext.Errorf("the rewrite must skip a row whose destination changed, got %+v %v", outcome, rewriteError)
	}
}

const (
	sidecarURL          = "https://sidecar.example.com:8443"
	currentSigningKeyID = "0123456789abcdef0123456789abcdef"
	nextSigningKeyID    = "fedcba9876543210fedcba9876543210"
)

// sealSidecarKeys gives the engine a sidecar whose current and next signing
// keys are sealed by sealingKeyring under the destination-bound associated
// data. The secret bytes are opaque to the rotation, so a marker is enough.
func sealSidecarKeys(testContext *testing.T, fixture rotationFixture, sealingKeyring *Keyring, engineID int64) {
	testContext.Helper()
	currentCiphertext, currentKeyringKeyID, _ := sealingKeyring.Seal([]byte("current-signing-secret"),
		EngineSidecarKeyAssociatedData(engineID, sidecarURL, currentSigningKeyID))
	nextCiphertext, nextKeyringKeyID, _ := sealingKeyring.Seal([]byte("next-signing-secret"),
		EngineSidecarKeyAssociatedData(engineID, sidecarURL, nextSigningKeyID))
	if _, updateError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_sidecar_url = ?, engine_sidecar_spki_sha256 = repeat('ab', 32),
		 engine_sidecar_signing_key_kid = ?, engine_sidecar_signing_public_key = 'public-current',
		 engine_sidecar_signing_key_sealed = ?, engine_sidecar_signing_key_key_id = ?,
		 engine_sidecar_next_signing_key_kid = ?, engine_sidecar_next_signing_public_key = 'public-next',
		 engine_sidecar_next_signing_key_sealed = ?, engine_sidecar_next_signing_key_key_id = ?
		 WHERE engine_id = ?`,
		sidecarURL, currentSigningKeyID, currentCiphertext, currentKeyringKeyID,
		nextSigningKeyID, nextCiphertext, nextKeyringKeyID, engineID); updateError != nil {
		testContext.Fatalf("seal sidecar keys: %v", updateError)
	}
}

func TestRotateResealsSidecarKeys(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	engineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "remote",
		destinationPasswordAssociatedData, destinationCredentialAssociatedData)
	sealSidecarKeys(testContext, fixture, fixture.retiredKeyring, engineID)

	report, rotateError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, false, testBatchSize)

	if rotateError != nil {
		testContext.Fatalf("rotate: %v", rotateError)
	}
	if report.Rewritten() != 4 {
		testContext.Errorf("expected both credentials and both sidecar keys rewritten, got %+v", report)
	}
	var currentCiphertext, nextCiphertext []byte
	var currentKeyringKeyID, nextKeyringKeyID string
	if scanError := fixture.database.QueryRowContext(context.Background(),
		`SELECT engine_sidecar_signing_key_sealed, engine_sidecar_signing_key_key_id,
		 engine_sidecar_next_signing_key_sealed, engine_sidecar_next_signing_key_key_id FROM engine WHERE engine_id = ?`, engineID).
		Scan(&currentCiphertext, &currentKeyringKeyID, &nextCiphertext, &nextKeyringKeyID); scanError != nil {
		testContext.Fatalf("load sidecar keys: %v", scanError)
	}
	rotatedKeyID := fixture.rotatingKeyring.CurrentKeyID()
	if currentKeyringKeyID != rotatedKeyID || nextKeyringKeyID != rotatedKeyID {
		testContext.Errorf("both sidecar keys must use the current key, got %q and %q", currentKeyringKeyID, nextKeyringKeyID)
	}
	currentSecret, currentOpenError := fixture.rotatingKeyring.Open(currentCiphertext, currentKeyringKeyID,
		EngineSidecarKeyAssociatedData(engineID, sidecarURL, currentSigningKeyID))
	nextSecret, nextOpenError := fixture.rotatingKeyring.Open(nextCiphertext, nextKeyringKeyID,
		EngineSidecarKeyAssociatedData(engineID, sidecarURL, nextSigningKeyID))
	if currentOpenError != nil || string(currentSecret) != "current-signing-secret" || nextOpenError != nil || string(nextSecret) != "next-signing-secret" {
		testContext.Errorf("the resealed keys must open under their own kid and destination, got %v %v", currentOpenError, nextOpenError)
	}
}

func TestEngineSidecarKeyAssociatedDataBindsDestinationAndKeyID(testContext *testing.T) {
	expectedAssociatedData := "engine.sidecar_signing_key:7:32:https://sidecar.example.com:8443:4:kid1"
	if obtainedAssociatedData := string(EngineSidecarKeyAssociatedData(7, "https://SIDECAR.example.com:8443", "kid1")); obtainedAssociatedData != expectedAssociatedData {
		testContext.Errorf("expected %q, got %q", expectedAssociatedData, obtainedAssociatedData)
	}
	referenceAssociatedData := EngineSidecarKeyAssociatedData(7, sidecarURL, currentSigningKeyID)
	for caseName, otherAssociatedData := range map[string][]byte{
		"other engine":      EngineSidecarKeyAssociatedData(8, sidecarURL, currentSigningKeyID),
		"other destination": EngineSidecarKeyAssociatedData(7, "https://attacker.example.com:8443", currentSigningKeyID),
		"other port":        EngineSidecarKeyAssociatedData(7, "https://sidecar.example.com:9443", currentSigningKeyID),
		"other kid":         EngineSidecarKeyAssociatedData(7, sidecarURL, nextSigningKeyID),
	} {
		if bytes.Equal(referenceAssociatedData, otherAssociatedData) {
			testContext.Errorf("%s must change the associated data", caseName)
		}
	}
}

// TestEncryptedColumnsRegistryCoversEverySealedColumn fails when the schema
// gains a sealed or ciphertext column that the rotation registry does not
// list: such a column would be silently left under a retired key.
func TestEncryptedColumnsRegistryCoversEverySealedColumn(testContext *testing.T) {
	database := storetest.New(testContext)
	var sealedColumnNames []string
	if queryError := database.NewRaw(
		`SELECT table_name || '.' || column_name FROM information_schema.columns
		 WHERE table_schema = current_schema() AND data_type = 'bytea'
		 AND (column_name LIKE '%\_sealed' OR column_name LIKE '%\_ciphertext')`,
	).Scan(context.Background(), &sealedColumnNames); queryError != nil {
		testContext.Fatalf("list sealed columns: %v", queryError)
	}
	registeredColumnNames := map[string]bool{}
	for _, registeredColumn := range EncryptedColumns {
		registeredColumnNames[registeredColumn.Name()] = true
	}
	for _, sealedColumnName := range sealedColumnNames {
		if !registeredColumnNames[sealedColumnName] {
			testContext.Errorf("sealed column %s is missing from EncryptedColumns", sealedColumnName)
		}
	}
	if len(sealedColumnNames) != len(registeredColumnNames) {
		testContext.Errorf("the registry lists %d columns, the schema has %d sealed columns: %v", len(registeredColumnNames), len(sealedColumnNames), sealedColumnNames)
	}
}
