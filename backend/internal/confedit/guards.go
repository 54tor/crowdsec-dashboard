package confedit

func findIndirectionChange(original, submitted *parsedText) bool {
	for indirection := range submitted.indirections {
		if !original.indirections[indirection] {
			return true
		}
	}
	return false
}

func findEndpointChange(original, submitted *parsedText) (int, bool) {
	changedLine := 0
	hasChange := false
	noteLine := func(line int) {
		if !hasChange || (line != 0 && (changedLine == 0 || line < changedLine)) {
			changedLine = line
		}
		hasChange = true
	}
	for key, submittedValue := range submitted.endpoints {
		originalValue, found := original.endpoints[key]
		if !found || originalValue.canonical != submittedValue.canonical {
			noteLine(submittedValue.line)
		}
	}
	for key := range original.endpoints {
		if _, found := submitted.endpoints[key]; !found {
			noteLine(0)
		}
	}
	return changedLine, hasChange
}
