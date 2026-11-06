package confedit

type firstChange struct {
	line  int
	found bool
}

func (change *firstChange) note(line int) {
	if !change.found || (line != 0 && (change.line == 0 || line < change.line)) {
		change.line = line
	}
	change.found = true
}

func findIndirectionChange(original, submitted *parsedText) firstChange {
	var change firstChange
	for record, submittedOccurrences := range submitted.indirections {
		if original.indirections[record].count != submittedOccurrences.count {
			change.note(submittedOccurrences.firstLine)
		}
	}
	for record := range original.indirections {
		if _, found := submitted.indirections[record]; !found {
			change.note(0)
		}
	}
	return change
}

func findEndpointChange(original, submitted *parsedText) firstChange {
	var change firstChange
	for key, submittedValue := range submitted.endpoints {
		originalValue, found := original.endpoints[key]
		if !found || originalValue.canonical != submittedValue.canonical {
			change.note(submittedValue.line)
		}
	}
	for key := range original.endpoints {
		if _, found := submitted.endpoints[key]; !found {
			change.note(0)
		}
	}
	return change
}
