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
