package confedit

import (
	"errors"
	"fmt"
	"strings"
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
			name:           "refusesCommentMarkerWithoutOriginalComment",
			original:       "password: s\n",
			submitted:      "# note password: [REDACTED]\npassword: [REDACTED]\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "restoresCommentSecretKeptInPlace",
			original:       "# see postgres://u:p@h\nname: x\n",
			submitted:      "# see postgres://[REDACTED]@h\nname: y\n",
			valeurAttendue: "# see postgres://u:p@h\nname: y\n",
		},
		{
			name:           "refusesCommentSecretMovedIntoBlockScalar",
			original:       "# see postgres://u:p@h\nname: x\n",
			submitted:      "note: |\n  # see postgres://[REDACTED]@h\nname: x\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "refusesCommentSecretMovedUnderAnotherKey",
			original:       "# see postgres://u:p@h\nname: x\n",
			submitted:      "name: x\n# see postgres://[REDACTED]@h\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "keepsSecretsWhenIdenticalLookingItemsAreSwappedByUniqueKey",
			original:       "users:\n  - enabled: true\n    name: a\n    password: s1\n  - enabled: true\n    name: b\n    password: s2\n",
			submitted:      "users:\n  - enabled: true\n    name: b\n    password: [REDACTED]\n  - enabled: true\n    name: a\n    password: [REDACTED]\n",
			valeurAttendue: "users:\n  - enabled: true\n    name: b\n    password: s2\n  - enabled: true\n    name: a\n    password: s1\n",
		},
		{
			name:           "refusesPositionalItemWhenNonSecretScalarsChanged",
			original:       "users:\n  - enabled: true\n    password: s1\n  - enabled: true\n    password: s2\n",
			submitted:      "users:\n  - enabled: false\n    password: [REDACTED]\n  - enabled: true\n    password: [REDACTED]\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "keepsSecretsInNestedListsWhenOuterItemsAreSwapped",
			original:       "groups:\n  - name: g1\n    users:\n      - id: 1\n        password: s1\n  - name: g2\n    users:\n      - id: 1\n        password: s2\n",
			submitted:      "groups:\n  - name: g2\n    users:\n      - id: 1\n        password: [REDACTED]\n  - name: g1\n    users:\n      - id: 1\n        password: [REDACTED]\n",
			valeurAttendue: "groups:\n  - name: g2\n    users:\n      - id: 1\n        password: s2\n  - name: g1\n    users:\n      - id: 1\n        password: s1\n",
		},
		{
			name:           "refusesNestedSecretWhenAncestorUrlChanged",
			original:       "http:\n  url: https://a.example.com\n  headers:\n    Authorization: s\n",
			submitted:      "http:\n  url: https://evil.example.com\n  headers:\n    Authorization: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "restoresNestedSecretWhenOnlyUnrelatedAncestorValueChanged",
			original:       "http:\n  url: https://a.example.com\n  retries: 1\n  headers:\n    Authorization: s\n",
			submitted:      "http:\n  url: https://a.example.com\n  retries: 2\n  headers:\n    Authorization: [REDACTED]\n",
			valeurAttendue: "http:\n  url: https://a.example.com\n  retries: 2\n  headers:\n    Authorization: s\n",
		},
		{
			name:           "refusesRestoreWhenSubmittedIntroducesAlias",
			original:       "base: &b\n  url: https://a.example.com\nother:\n  token: s\n",
			submitted:      "base: &b\n  url: https://a.example.com\nother:\n  url: *b\n  token: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesRestoreWhenSubmittedIntroducesMergeKey",
			original:       "base: &b\n  url: https://a.example.com\nother:\n  token: s\n",
			submitted:      "base: &b\n  url: https://a.example.com\nother:\n  <<: *b\n  token: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "keepsBlankLinesOfKeepChompedBlockInSequenceItem",
			original:       "items:\n  - password: |+\n      a\n\nname: x\n",
			submitted:      "items:\n  - password: [REDACTED]\nname: x\n",
			valeurAttendue: "items:\n  - password: |+\n      a\n\nname: x\n",
		},
		{
			name:           "keepsBlankLinesOfKeepChompedBlockWithAnchorAndTag",
			original:       "key: &a |+\n  a\n\nname: x\n",
			submitted:      "key: [REDACTED]\nname: x\n",
			valeurAttendue: "key: &a |+\n  a\n\nname: x\n",
		},
		{
			name:           "restoresOriginalLineEndingsWhenSubmittedHasNoMarker",
			original:       "\ufeffa: 1\r\n",
			submitted:      "a: 2\n",
			valeurAttendue: "\ufeffa: 2\r\n",
		},
		{
			name:           "refusesItemWhenNestedNonSecretSubtreeIsSwapped",
			original:       "items:\n  - password: s1\n    sub:\n      label: a\n  - password: s2\n    sub:\n      label: b\n",
			submitted:      "items:\n  - password: [REDACTED]\n    sub:\n      label: b\n  - password: [REDACTED]\n    sub:\n      label: a\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "refusesItemWhenNestedHostSubtreeIsSwapped",
			original:       "items:\n  - password: s1\n    sub:\n      host: a\n  - password: s2\n    sub:\n      host: b\n",
			submitted:      "items:\n  - password: [REDACTED]\n    sub:\n      host: b\n  - password: [REDACTED]\n    sub:\n      host: a\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesWhenAnchoredSubtreeChanged",
			original:       "base: &b\n  label: good\nsvc:\n  <<: *b\n  password: s1\n",
			submitted:      "base: &b\n  label: evil\nsvc:\n  <<: *b\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "restoresWhenAnchorsAndAliasesAreUnchanged",
			original:       "base: &b\n  label: good\nsvc:\n  <<: *b\n  password: s1\n",
			submitted:      "base: &b\n  label: good\nsvc:\n  <<: *b\n  password: [REDACTED]\n  extra: 1\n",
			valeurAttendue: "base: &b\n  label: good\nsvc:\n  <<: *b\n  password: s1\n  extra: 1\n",
		},
		{
			name:           "refusesCommentMarkerInsideQuotedScalar",
			original:       "api:\n  url: http://lapi\n  # see postgres://u:p@h\n",
			submitted:      "api:\n  url: http://lapi\n  note: \"x\n  # see postgres://[REDACTED]@h\n  \"\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "refusesCommentMarkerBuildingLiveUrl",
			original:       "api:\n  url: http://lapi\n  # see postgres://u:p@h\n",
			submitted:      "api:\n  url: \"http://evil/?q=\n  # see postgres://[REDACTED]@h\n  \"\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesCommentSecretWhenEndpointChanged",
			original:       "url: http://a\n# see postgres://u:p@h\n",
			submitted:      "url: http://b\n# see postgres://[REDACTED]@h\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesPathsThatCollideWhenKeysContainSeparators",
			original:       "outputs:\n  smtp:\n    password: s1\n",
			submitted:      "outputs/smtp:\n    password: [REDACTED]\n",
			erreurAttendue: ErrRedactedWithoutOriginal,
		},
		{
			name:           "refusesBlockToFlowRestoration",
			original:       "auth:\n  password: ab\n",
			submitted:      "auth: {\n  password: [REDACTED]\n  }\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesAllSecretsWhenUnrelatedEndpointKeyChanges",
			original:       "listen: 1\nsvc:\n  password: s\n",
			submitted:      "listen: 2\nsvc:\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesWhenEndpointKeyIsRemoved",
			original:       "listen: 1\nsvc:\n  password: s\n",
			submitted:      "svc:\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
		},
		{
			name:           "refusesWhenNonScalarEndpointValueChanges",
			original:       "servers:\n  - a\nsvc:\n  password: s\n",
			submitted:      "servers:\n  - a\n  - b\nsvc:\n  password: [REDACTED]\n",
			erreurAttendue: ErrSecretContextChanged,
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

func TestMergeHandlesLargeListsWithoutBlowup(testingContext *testing.T) {
	var originalBuilder, submittedBuilder strings.Builder
	originalBuilder.WriteString("users:\n")
	submittedBuilder.WriteString("users:\n")
	for itemIndex := 0; itemIndex < 3000; itemIndex++ {
		originalBuilder.WriteString(fmt.Sprintf("  - name: user%d\n    password: secret%d\n", itemIndex, itemIndex))
		submittedBuilder.WriteString(fmt.Sprintf("  - name: user%d\n    password: [REDACTED]\n", itemIndex))
	}

	valeurObtenue, erreurObtenue := MergeRedactedValues([]byte(originalBuilder.String()), []byte(submittedBuilder.String()))

	if erreurObtenue != nil {
		testingContext.Fatalf("erreur inattendue %v", erreurObtenue)
	}
	if string(valeurObtenue) != originalBuilder.String() {
		testingContext.Fatalf("le contenu fusionne differe de l'original")
	}
}
