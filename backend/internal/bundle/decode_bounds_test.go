package bundle

import (
	"errors"
	"strings"
	"testing"
)

// repeatedArray is a JSON array holding elementCount copies of element.
func repeatedArray(element string, elementCount int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(element+",", elementCount), ",") + "]"
}

// documentWithValueCount builds {"sections":[[1,...],[1,...],...]} holding exactly totalValues JSON
// values: the object, the outer array, 80 inner arrays and the scalars they share. Object keys are
// not values.
func documentWithValueCount(totalValues int) string {
	const innerArrayCount = 80
	scalarCount := totalValues - 2 - innerArrayCount
	innerArrays := make([]string, 0, innerArrayCount)
	for arrayIndex := range innerArrayCount {
		scalarsInThisArray := scalarCount / innerArrayCount
		if arrayIndex < scalarCount%innerArrayCount {
			scalarsInThisArray++
		}
		innerArrays = append(innerArrays, repeatedArray("1", scalarsInThisArray))
	}
	return `{"sections":[` + strings.Join(innerArrays, ",") + `]}`
}

// A hostile 18 KB bundle with 6000 empty alerts would allocate 6000 decoded structs: the token walk
// refuses it first. ErrTooLarge (and not the ErrInvalid the missing header would give) proves the
// refusal happened before any header or struct decoding.
func TestDecodeRefusesAnArrayLongerThanTheCap(testContext *testing.T) {
	hostileBody := `{"alerts":` + repeatedArray("{}", MaxArrayLength+1000) + `}`
	if len(hostileBody) > 64<<10 {
		testContext.Fatalf("the hostile body must stay far below the byte cap, got %d bytes", len(hostileBody))
	}
	if _, decodeError := Decode(strings.NewReader(hostileBody), MaxBytes); !errors.Is(decodeError, ErrTooLarge) {
		testContext.Errorf("expected ErrTooLarge, got %v", decodeError)
	}
}

func TestDecodeAcceptsAnArrayAtTheCap(testContext *testing.T) {
	bodyAtTheCap := `{"alerts":` + repeatedArray("{}", MaxArrayLength) + `}`
	if _, decodeError := Decode(strings.NewReader(bodyAtTheCap), MaxBytes); errors.Is(decodeError, ErrTooLarge) {
		testContext.Errorf("an array of exactly %d elements must pass the structure check, got %v", MaxArrayLength, decodeError)
	}
}

func TestDecodeRefusesMoreValuesThanTheCap(testContext *testing.T) {
	if _, decodeError := Decode(strings.NewReader(documentWithValueCount(MaxValueCount+1)), MaxBytes); !errors.Is(decodeError, ErrTooLarge) {
		testContext.Errorf("expected ErrTooLarge for %d values, got %v", MaxValueCount+1, decodeError)
	}
	if _, decodeError := Decode(strings.NewReader(documentWithValueCount(MaxValueCount)), MaxBytes); errors.Is(decodeError, ErrTooLarge) {
		testContext.Errorf("exactly %d values must pass the structure check, got %v", MaxValueCount, decodeError)
	}
}

func TestDecodeCapsHaveTheirDocumentedValues(testContext *testing.T) {
	if MaxArrayLength != 5000 || MaxValueCount != 400000 {
		testContext.Errorf("unexpected caps: array %d, values %d", MaxArrayLength, MaxValueCount)
	}
}
