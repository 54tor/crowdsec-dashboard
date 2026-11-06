package confedit

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Loose upper bound: the inputs below took from seconds to minutes when every
// level re-serialised its whole subtree; a linear implementation needs a few
// milliseconds, so a generous bound keeps the test stable on slow machines.
const dureeMaximaleDeFusion = 2 * time.Second

func mesurerFusion(original, submitted string) (error, time.Duration) {
	debut := time.Now()
	_, erreurObtenue := MergeRedactedValues([]byte(original), []byte(submitted))
	return erreurObtenue, time.Since(debut)
}

func mappingImbrique(profondeur int, feuille string) string {
	return strings.Repeat("{host: ", profondeur) + feuille + strings.Repeat("}", profondeur)
}

func sequenceImbriquee(profondeur int) string {
	return strings.Repeat("[", profondeur) + "x" + strings.Repeat("]", profondeur)
}

func TestMergeRefusesDeeplyNestedInputQuickly(testingContext *testing.T) {
	casesDeTest := []struct {
		name      string
		original  string
		submitted string
	}{
		{
			name:      "nestedMappingsDepth2000",
			original:  "deep: " + mappingImbrique(2000, "x") + "\npassword: s1\n",
			submitted: "deep: " + mappingImbrique(2000, "x") + "\npassword: [REDACTED]\n",
		},
		{
			name:      "nestedMappingsDepth9000",
			original:  "deep: " + mappingImbrique(9000, "x") + "\npassword: s1\n",
			submitted: "deep: " + mappingImbrique(9000, "x") + "\npassword: [REDACTED]\n",
		},
		{
			// Only the submitted side is deep: the shallow original must not
			// make the deep submission acceptable.
			name:      "deepSubmissionAgainstShallowOriginal",
			original:  "deep: x\npassword: s1\n",
			submitted: "deep: " + mappingImbrique(9000, "x") + "\npassword: [REDACTED]\n",
		},
		{
			name:      "nestedSequencesDepth9000",
			original:  "deep: " + sequenceImbriquee(9000) + "\npassword: s1\n",
			submitted: "deep: " + sequenceImbriquee(9000) + "\npassword: [REDACTED]\n",
		},
	}

	for _, casDeTestCourant := range casesDeTest {
		testingContext.Run(casDeTestCourant.name, func(testingContext *testing.T) {
			erreurObtenue, dureeObtenue := mesurerFusion(casDeTestCourant.original, casDeTestCourant.submitted)

			if !errors.Is(erreurObtenue, ErrNestingTooDeep) {
				testingContext.Fatalf("erreur obtenue %v, attendue %v", erreurObtenue, ErrNestingTooDeep)
			}
			if dureeObtenue > dureeMaximaleDeFusion {
				testingContext.Fatalf("fusion trop lente : %v", dureeObtenue)
			}
		})
	}
}

func TestMergeAcceptsNestingUpToTheLimit(testingContext *testing.T) {
	// The document node and the root mapping take two levels, the leaf scalar one more.
	profondeurAcceptee := maxNestingDepth - 3
	original := "deep: " + mappingImbrique(profondeurAcceptee, "x") + "\npassword: s1\n"
	submitted := "deep: " + mappingImbrique(profondeurAcceptee, "x") + "\npassword: [REDACTED]\n"

	valeurObtenue, erreurObtenue := MergeRedactedValues([]byte(original), []byte(submitted))

	if erreurObtenue != nil {
		testingContext.Fatalf("erreur inattendue %v", erreurObtenue)
	}
	if string(valeurObtenue) != original {
		testingContext.Fatalf("obtenu %q, attendu %q", valeurObtenue, original)
	}
}

func TestMergeHandlesWideFirstListItemQuickly(testingContext *testing.T) {
	// No key of the item has a plain scalar value, so every key is tried as a
	// list discriminator: each attempt must not rescan the whole item. 11000
	// keys keep the text just under the 256 KiB editor limit; the quadratic
	// scan needed about 1.3 s there, the linear one about 0.4 s, hence the
	// tighter bound than for the depth cases.
	const dureeMaximalePourElementLarge = time.Second
	var itemBuilder strings.Builder
	for indexCle := 0; indexCle < 11000; indexCle++ {
		itemBuilder.WriteString(fmt.Sprintf("    field%05d: [value]\n", indexCle))
	}
	original := "items:\n  - password: s1\n" + itemBuilder.String()
	submitted := "items:\n  - password: [REDACTED]\n" + itemBuilder.String()

	erreurObtenue, dureeObtenue := mesurerFusion(original, submitted)

	if erreurObtenue != nil {
		testingContext.Fatalf("erreur inattendue %v", erreurObtenue)
	}
	if dureeObtenue > dureeMaximalePourElementLarge {
		testingContext.Fatalf("fusion trop lente : %v", dureeObtenue)
	}
}
