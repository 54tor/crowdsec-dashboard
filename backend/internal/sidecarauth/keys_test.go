package sidecarauth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestGenerateSigningKeyUsesARandomHexKeyID(testContext *testing.T) {
	firstKey := mustGenerateSigningKey(testContext)
	secondKey := mustGenerateSigningKey(testContext)

	if len(firstKey.KeyID) != 32 {
		testContext.Fatalf("expected a 16-byte hex kid, got %d characters", len(firstKey.KeyID))
	}
	if _, decodeError := hex.DecodeString(firstKey.KeyID); decodeError != nil {
		testContext.Fatalf("kid is not hex: %v", decodeError)
	}
	if firstKey.KeyID == secondKey.KeyID || firstKey.PublicKeyHex() == secondKey.PublicKeyHex() {
		testContext.Fatal("two generated keys must differ")
	}
}

func TestParseSigningKeyRestoresTheSameKeyPair(testContext *testing.T) {
	generatedKey := mustGenerateSigningKey(testContext)

	parsedKey, parseError := ParseSigningKey(generatedKey.KeyID, generatedKey.SecretBytes())

	if parseError != nil {
		testContext.Fatalf("ParseSigningKey: %v", parseError)
	}
	if parsedKey.KeyID != generatedKey.KeyID || parsedKey.PublicKeyHex() != generatedKey.PublicKeyHex() {
		testContext.Fatal("parsed key must keep the kid and the key pair")
	}
	if !bytes.Equal(parsedKey.SecretBytes(), generatedKey.SecretBytes()) {
		testContext.Fatal("parsed key must keep the secret bytes")
	}
}

func TestParseSigningKeyRefusesMalformedInput(testContext *testing.T) {
	generatedKey := mustGenerateSigningKey(testContext)
	secretBytes := generatedKey.SecretBytes()
	mismatchedPair := append([]byte{}, secretBytes...)
	mismatchedPair[63] ^= 0x01
	malformedInputs := map[string]struct {
		keyID       string
		secretBytes []byte
	}{
		"empty kid":          {keyID: "", secretBytes: secretBytes},
		"kid with a space":   {keyID: "kid one", secretBytes: secretBytes},
		"kid with a newline": {keyID: "kid\n", secretBytes: secretBytes},
		"short secret":       {keyID: generatedKey.KeyID, secretBytes: secretBytes[:32]},
		"empty secret":       {keyID: generatedKey.KeyID, secretBytes: nil},
		"mismatched pair":    {keyID: generatedKey.KeyID, secretBytes: mismatchedPair},
	}
	for caseName, malformedInput := range malformedInputs {
		testContext.Run(caseName, func(subtestContext *testing.T) {
			_, parseError := ParseSigningKey(malformedInput.keyID, malformedInput.secretBytes)

			if parseError == nil {
				subtestContext.Fatal("expected an error")
			}
			if strings.Contains(parseError.Error(), hex.EncodeToString(secretBytes[:8])) {
				subtestContext.Fatal("the error must not carry secret material")
			}
		})
	}
}

func TestTrustedKeyLineNamesTheKidAndPublicKey(testContext *testing.T) {
	generatedKey := mustGenerateSigningKey(testContext)

	trustedKeyLine := generatedKey.TrustedKeyLine()

	expectedLine := generatedKey.KeyID + " " + generatedKey.PublicKeyHex()
	if trustedKeyLine != expectedLine {
		testContext.Fatalf("expected %q, got %q", expectedLine, trustedKeyLine)
	}
	if len(generatedKey.PublicKeyHex()) != 64 {
		testContext.Fatalf("expected a 32-byte hex public key, got %d characters", len(generatedKey.PublicKeyHex()))
	}
	if generatedKey.PublicKeyHex() != generatedKey.secret.Public().ExportHex() {
		testContext.Fatal("public key hex must be the public half of the secret key")
	}
}

func TestSigningKeyNeverFormatsItsSecret(testContext *testing.T) {
	generatedKey := mustGenerateSigningKey(testContext)
	secretHex := hex.EncodeToString(generatedKey.SecretBytes())
	seedHex := secretHex[:64]
	expectedText := "sidecarauth.SigningKey{KeyID:" + generatedKey.KeyID + "}"

	var logOutput bytes.Buffer
	slog.New(slog.NewJSONHandler(&logOutput, nil)).Info("key", "signing_key", generatedKey)
	jsonOutput, marshalError := json.Marshal(generatedKey)
	if marshalError != nil {
		testContext.Fatalf("json.Marshal: %v", marshalError)
	}
	// %d and %x would print the raw secret bytes of a struct that only had a
	// String method, so every verb must go through the redacted rendering.
	fmtRenderings := map[string]string{
		"%v":      fmt.Sprintf("%v", generatedKey),
		"%+v":     fmt.Sprintf("%+v", generatedKey),
		"%#v":     fmt.Sprintf("%#v", generatedKey),
		"%s":      fmt.Sprintf("%s", generatedKey),
		"%x":      fmt.Sprintf("%x", generatedKey),
		"%d":      fmt.Sprintf("%d", generatedKey),
		"pointer": fmt.Sprintf("%+v", &generatedKey),
	}
	for verbName, rendering := range fmtRenderings {
		if rendering != expectedText {
			testContext.Fatalf("%s: expected %q, got %q", verbName, expectedText, rendering)
		}
	}
	for renderingName, rendering := range map[string]string{"slog": logOutput.String(), "json": string(jsonOutput)} {
		lowercaseRendering := strings.ToLower(rendering)
		if strings.Contains(lowercaseRendering, secretHex) || strings.Contains(lowercaseRendering, seedHex) {
			testContext.Fatalf("%s rendering leaks the secret", renderingName)
		}
	}
	if !strings.Contains(logOutput.String(), expectedText) {
		testContext.Fatalf("slog must render %q, got %s", expectedText, logOutput.String())
	}
}
