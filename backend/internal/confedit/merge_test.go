package confedit

import (
	"errors"
	"testing"
)

func TestMergeRedactedValues(testingContext *testing.T) {
	casesDeTest := []struct {
		name           string
		original       string
		submitted      string
		valeurAttendue string
		erreurAttendue error
	}{
		{
			name:           "keepsOriginalSecretWhenMaskedValueIsUnchanged",
			original:       "user: bob\npassword: hunter2\n",
			submitted:      "user: alice\npassword: [REDACTED]\n",
			valeurAttendue: "user: alice\npassword: hunter2\n",
		},
		{
			name:           "keepsMultiLineSecretBlock",
			original:       "key: |\n  line1\n  line2\nname: x\n",
			submitted:      "key: [REDACTED]\nname: y\n",
			valeurAttendue: "key: |\n  line1\n  line2\nname: y\n",
		},
		{
			name:           "replacesSecretWhenUserTypesNewValue",
			original:       "password: hunter2\n",
			submitted:      "password: brandnew\n",
			valeurAttendue: "password: brandnew\n",
		},
		{
			name:           "refusesMarkerOnKeyWithoutOriginalSecret",
			original:       "name: x\n",
			submitted:      "password: [REDACTED]\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "refusesMarkerWhenOriginalHasNoSecretAtThatKey",
			original:       "first:\n  password: s1\nsecond:\n  name: x\n",
			submitted:      "first:\n  password: [REDACTED]\nsecond:\n  password: [REDACTED]\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "keepsUrlCredentials",
			original:       "url: postgres://user:pass@host/db\n",
			submitted:      "url: postgres://[REDACTED]@host/db\n",
			valeurAttendue: "url: postgres://user:pass@host/db\n",
		},
		{
			name:           "handlesInlineEntries",
			original:       "auth: {user: a, password: x}\n",
			submitted:      "auth: {user: a, password: [REDACTED]}\n",
			valeurAttendue: "auth: {user: a, password: x}\n",
		},
		{
			name:           "keepsSecretWhenLinesAreInsertedAbove",
			original:       "db:\n  password: s1\n",
			submitted:      "extra: 1\nother:\n  note: y\ndb:\n  password: [REDACTED]\n",
			valeurAttendue: "extra: 1\nother:\n  note: y\ndb:\n  password: s1\n",
		},
		{
			name:           "matchesSecretsByParentKeyWhenReordered",
			original:       "a:\n  password: sa\nb:\n  password: sb\n",
			submitted:      "b:\n  password: [REDACTED]\na:\n  password: [REDACTED]\n",
			valeurAttendue: "b:\n  password: sb\na:\n  password: sa\n",
		},
		{
			name:           "keepsEachSecretWhenListItemIsDeleted",
			original:       "users:\n  - name: a\n    password: s1\n  - name: b\n    password: s2\n",
			submitted:      "users:\n  - name: b\n    password: [REDACTED]\n",
			valeurAttendue: "users:\n  - name: b\n    password: s2\n",
		},
		{
			name:           "keepsEachSecretWhenListItemsAreSwapped",
			original:       "users:\n  - name: a\n    password: s1\n  - name: b\n    password: s2\n",
			submitted:      "users:\n  - name: b\n    password: [REDACTED]\n  - name: a\n    password: [REDACTED]\n",
			valeurAttendue: "users:\n  - name: b\n    password: s2\n  - name: a\n    password: s1\n",
		},
		{
			name:           "refusesMarkerOnNewListItemAfterDeletion",
			original:       "users:\n  - name: a\n    password: s1\n  - name: b\n    password: s2\n",
			submitted:      "users:\n  - name: b\n    password: [REDACTED]\n  - name: c\n    password: [REDACTED]\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "refusesIndexedListWhenItemCountChanged",
			original:       "users:\n  - password: s1\n  - password: s2\n",
			submitted:      "users:\n  - password: [REDACTED]\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "keepsSecretsUnderAnchoredAndCommentedParentsWhenReordered",
			original:       "a: &x\n  password: sa\nb: # note\n  password: sb\nc: !!map\n  password: sc\n",
			submitted:      "c: !!map\n  password: [REDACTED]\nb: # note\n  password: [REDACTED]\na: &x\n  password: [REDACTED]\n",
			valeurAttendue: "c: !!map\n  password: sc\nb: # note\n  password: sb\na: &x\n  password: sa\n",
		},
		{
			name:           "keepsTrailingBlankLinesOfKeepChompedBlock",
			original:       "key: |+\n  a\n\nname: x\n",
			submitted:      "key: [REDACTED]\nname: x\n",
			valeurAttendue: "key: |+\n  a\n\nname: x\n",
		},
		{
			name:           "mergesCrlfContentWithBomAndRestoresOriginalStyle",
			original:       "\ufeffpassword: s\r\nname: a\r\n",
			submitted:      "password: [REDACTED]\nname: b\n",
			valeurAttendue: "\ufeffpassword: s\r\nname: b\r\n",
		},
		{
			name:           "mergesSubmittedCrlfAgainstLfOriginal",
			original:       "password: s\nname: a\n",
			submitted:      "\ufeffpassword: [REDACTED]\r\nname: b\r\n",
			valeurAttendue: "password: s\nname: b\n",
		},
		{
			name:           "consumesDuplicateIdenticalLinesInOrder",
			original:       "password: s1\npassword: s2\n",
			submitted:      "password: [REDACTED]\npassword: [REDACTED]\n",
			valeurAttendue: "password: s1\npassword: s2\n",
		},
		{
			name:           "refusesRestoringSecretWhenSiblingUrlChanged",
			original:       "notify:\n  url: https://a.example.com\n  token: s\n",
			submitted:      "notify:\n  url: https://evil.example.com\n  token: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "restoresSecretWhenOnlyUnrelatedSiblingChanged",
			original:       "notify:\n  url: https://a.example.com\n  label: one\n  token: s\n",
			submitted:      "notify:\n  url: https://a.example.com\n  label: two\n  token: [REDACTED]\n",
			valeurAttendue: "notify:\n  url: https://a.example.com\n  label: two\n  token: s\n",
		},
		{
			name:           "keepsCommentLineWithMarkerVerbatim",
			original:       "password: s\n",
			submitted:      "# note password: [REDACTED]\npassword: [REDACTED]\n",
			valeurAttendue: "# note password: [REDACTED]\npassword: s\n",
		},
	}

	for _, casDeTestCourant := range casesDeTest {
		testingContext.Run(casDeTestCourant.name, func(testingContext *testing.T) {
			valeurObtenue, erreurObtenue := MergeRedactedValues([]byte(casDeTestCourant.original), []byte(casDeTestCourant.submitted))

			if !errors.Is(erreurObtenue, casDeTestCourant.erreurAttendue) {
				testingContext.Fatalf("erreur obtenue %v, attendue %v", erreurObtenue, casDeTestCourant.erreurAttendue)
			}
			if casDeTestCourant.erreurAttendue == nil && string(valeurObtenue) != casDeTestCourant.valeurAttendue {
				testingContext.Fatalf("obtenu %q, attendu %q", valeurObtenue, casDeTestCourant.valeurAttendue)
			}
		})
	}
}

func TestMergeErrorCarriesSubmittedLineNumber(testingContext *testing.T) {
	_, erreurObtenue := MergeRedactedValues([]byte("name: x\n"), []byte("name: x\npassword: [REDACTED]\n"))

	var erreurDeFusion *MergeError
	if !errors.As(erreurObtenue, &erreurDeFusion) {
		testingContext.Fatalf("erreur de fusion attendue, obtenu %v", erreurObtenue)
	}
	if erreurDeFusion.Line != 2 {
		testingContext.Fatalf("ligne obtenue %d, attendue 2", erreurDeFusion.Line)
	}
}
