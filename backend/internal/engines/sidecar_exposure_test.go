package engines

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type sealedSidecarKeys struct {
	CurrentSealed []byte `bun:"engine_sidecar_signing_key_sealed"`
	NextSealed    []byte `bun:"engine_sidecar_next_signing_key_sealed"`
}

func loadSealedSidecarKeys(testContext *testing.T, fixture testFixture, engineID int64) sealedSidecarKeys {
	testContext.Helper()
	var sealedKeys sealedSidecarKeys
	if scanError := fixture.database.NewRaw(`SELECT engine_sidecar_signing_key_sealed, engine_sidecar_next_signing_key_sealed
		FROM engine WHERE engine_id = ?`, engineID).Scan(context.Background(), &sealedKeys); scanError != nil {
		testContext.Fatalf("load sealed sidecar keys: %v", scanError)
	}
	if len(sealedKeys.CurrentSealed) == 0 || len(sealedKeys.NextSealed) == 0 {
		testContext.Fatal("both sealed keys must be stored")
	}
	return sealedKeys
}

// Every textual shape a byte slice takes when printed or marshalled: the raw
// bytes, hexadecimal, the base64 of encoding/json and the decimal list of %v.
func forbiddenSealedFragments(sealedBytes []byte) []string {
	decimalList := strings.Trim(fmt.Sprint(sealedBytes), "[]")
	return []string{string(sealedBytes), hex.EncodeToString(sealedBytes), base64.StdEncoding.EncodeToString(sealedBytes), decimalList}
}

func renderedEngineForms(testContext *testing.T, renderedValue any) map[string]string {
	testContext.Helper()
	marshalledValue, marshalError := json.Marshal(renderedValue)
	if marshalError != nil {
		testContext.Fatalf("marshal: %v", marshalError)
	}
	return map[string]string{
		"%v":   fmt.Sprintf("%v", renderedValue),
		"%+v":  fmt.Sprintf("%+v", renderedValue),
		"%#v":  fmt.Sprintf("%#v", renderedValue),
		"json": string(marshalledValue),
	}
}

func TestListAndGetNeverCarryTheSealedOrSecretSidecarKeys(testContext *testing.T) {
	fixture := newFixture(testContext)
	ctx := context.Background()
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	mustConfigureSidecar(testContext, fixture, "edge-1", firstSidecarPin)
	if _, stageError := fixture.repository.StageSidecarKey(ctx, "edge-1"); stageError != nil {
		testContext.Fatalf("stage: %v", stageError)
	}
	currentKey, nextKey := mustOpenSidecarKeys(testContext, fixture, createdEngine.ID)
	sealedKeys := loadSealedSidecarKeys(testContext, fixture, createdEngine.ID)
	forbiddenFragments := []string{hex.EncodeToString(currentKey.SecretBytes()), hex.EncodeToString(nextKey.SecretBytes())}
	forbiddenFragments = append(forbiddenFragments, forbiddenSealedFragments(sealedKeys.CurrentSealed)...)
	forbiddenFragments = append(forbiddenFragments, forbiddenSealedFragments(sealedKeys.NextSealed)...)

	listedEngines, listError := fixture.repository.List(ctx)
	if listError != nil {
		testContext.Fatalf("list: %v", listError)
	}
	fetchedEngine, getError := fixture.repository.Get(ctx, "edge-1")
	if getError != nil || fetchedEngine.Sidecar == nil || fetchedEngine.Sidecar.NextKeyID == "" {
		testContext.Fatalf("get: %+v %v", fetchedEngine.Sidecar, getError)
	}
	renderedSources := map[string]any{"list": listedEngines, "get": fetchedEngine}
	for sourceLabel, renderedSource := range renderedSources {
		for formatLabel, renderedText := range renderedEngineForms(testContext, renderedSource) {
			for _, forbiddenFragment := range forbiddenFragments {
				if strings.Contains(renderedText, forbiddenFragment) {
					testContext.Errorf("%s rendered with %s carries a sealed or secret key", sourceLabel, formatLabel)
				}
			}
		}
	}
}

// Pins the public shape of a sidecar: a new field (a sealed or secret key) must
// fail here and be reviewed before it can reach a view or a log.
func TestSidecarExposesOnlyItsPublicFields(testContext *testing.T) {
	expectedFieldNames := []string{"URL", "SPKISHA256", "KeyID", "PublicKeyHex", "NextKeyID", "NextPublicKeyHex"}
	sidecarType := reflect.TypeFor[Sidecar]()
	obtainedFieldNames := make([]string, 0, sidecarType.NumField())
	for fieldIndex := range sidecarType.NumField() {
		obtainedFieldNames = append(obtainedFieldNames, sidecarType.Field(fieldIndex).Name)
	}
	if !slices.Equal(obtainedFieldNames, expectedFieldNames) {
		testContext.Errorf("expected the sidecar fields %v, got %v", expectedFieldNames, obtainedFieldNames)
	}
}
