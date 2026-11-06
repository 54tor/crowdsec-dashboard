package confedit

import (
	"errors"
	"testing"
)

// Each indirection (anchor, alias, merge key) is bound to the path where it
// appears: an indirection the original already uses must not be movable to
// another location, otherwise a restored secret could follow another endpoint.
func TestMergeBindsIndirectionsToTheirLocation(testingContext *testing.T) {
	casesDeTest := []struct {
		name           string
		original       string
		submitted      string
		valeurAttendue string
		erreurAttendue error
	}{
		{
			name:           "refusesWhenMergeKeysAreSwappedBetweenServices",
			original:       "prod: &p\n  host: prod.example\ndev: &d\n  host: dev.example\nsvc_prod:\n  <<: *p\n  password: s1\nsvc_dev:\n  <<: *d\n  password: s2\n",
			submitted:      "prod: &p\n  host: prod.example\ndev: &d\n  host: dev.example\nsvc_prod:\n  <<: *d\n  password: [REDACTED]\nsvc_dev:\n  <<: *p\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesWhenFlowAnchoredMergeKeysAreSwapped",
			original:       "prod: &p {host: prod.example}\ndev: &d {host: dev.example}\nsvc_prod:\n  <<: *p\n  password: s1\nsvc_dev:\n  <<: *d\n  password: s2\n",
			submitted:      "prod: &p {host: prod.example}\ndev: &d {host: dev.example}\nsvc_prod:\n  <<: *d\n  password: [REDACTED]\nsvc_dev:\n  <<: *p\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesWhenPlainAliasesAreSwappedBetweenServices",
			original:       "prod: &p\n  host: prod.example\ndev: &d\n  host: dev.example\nsvc_prod:\n  conn: *p\n  password: s1\nsvc_dev:\n  conn: *d\n  password: s2\n",
			submitted:      "prod: &p\n  host: prod.example\ndev: &d\n  host: dev.example\nsvc_prod:\n  conn: *d\n  password: [REDACTED]\nsvc_dev:\n  conn: *p\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesWhenAnchorIsMovedToAnotherKey",
			original:       "a: &x\n  host: one\nb:\n  host: two\nsvc:\n  conn: *x\n  password: s1\n",
			submitted:      "a:\n  host: one\nb: &x\n  host: two\nsvc:\n  conn: *x\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesWhenAliasResolvesToAnotherDuplicateAnchor",
			original:       "a: &x\n  label: one\nb:\n  conn: *x\n  password: s1\nc: &x\n  label: two\n",
			submitted:      "c: &x\n  label: two\nb:\n  conn: *x\n  password: [REDACTED]\na: &x\n  label: one\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesWhenSubmittedRemovesAlias",
			original:       "base: &b\n  label: good\nsvc:\n  <<: *b\n  password: s1\n",
			submitted:      "base: &b\n  label: good\nsvc:\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "restoresWhenIndirectionsStayInPlaceAndKeysAreReordered",
			original:       "prod: &p\n  host: prod.example\nsvc_prod:\n  <<: *p\n  password: s1\n",
			submitted:      "prod: &p\n  host: prod.example\nsvc_prod:\n  password: [REDACTED]\n  <<: *p\n",
			valeurAttendue: "prod: &p\n  host: prod.example\nsvc_prod:\n  password: s1\n  <<: *p\n",
		},
		{
			// Complex (non-scalar) keys used to share the empty identity, so
			// swapping two of them moved each secret under the other key.
			name:           "keepsSecretsUnderTheirOwnComplexKeyWhenSwapped",
			original:       "? [a]\n: {password: s1}\n? [b]\n: {password: s2}\n",
			submitted:      "? [b]\n: {password: [REDACTED]}\n? [a]\n: {password: [REDACTED]}\n",
			valeurAttendue: "? [b]\n: {password: s2}\n? [a]\n: {password: s1}\n",
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
