package enginesync

import (
	"slices"
	"time"
)

type offerBook map[string]map[Target]time.Duration

func collectOffers(classifiedSnapshots []classifiedSnapshot, rules Rules) (offerBook, []Skip) {
	offers := offerBook{}
	var skips []Skip
	for _, sourceSnapshot := range classifiedSnapshots {
		if sourceSnapshot.State != ReadComplete {
			continue
		}
		sourceOffers := make(map[Target]time.Duration, len(sourceSnapshot.natives))
		for _, localBan := range sourceSnapshot.natives {
			shareable, reason := IsShareable(localBan, rules)
			if !shareable {
				skips = append(skips, Skip{Engine: sourceSnapshot.Engine, Target: localBan.Target, Reason: reason})
				continue
			}
			sourceOffers[localBan.Target] = max(sourceOffers[localBan.Target], localBan.Remaining)
		}
		offers[sourceSnapshot.Engine] = sourceOffers
	}
	return offers, skips
}

func (offers offerBook) isComplete(sourceName string) bool {
	_, complete := offers[sourceName]
	return complete
}

func (offers offerBook) remaining(sourceName string, target Target) (time.Duration, bool) {
	remaining, offered := offers[sourceName][target]
	return remaining, offered
}

func (offers offerBook) candidatesFor(engineName string, guardedSources map[string]bool) []Target {
	offerCount := 0
	for _, sourceOffers := range offers {
		offerCount += len(sourceOffers)
	}
	seenTargets := make(map[Target]bool, offerCount)
	candidates := make([]Target, 0, offerCount)
	for sourceName, sourceOffers := range offers {
		if sourceName == engineName || guardedSources[sourceName] {
			continue
		}
		for target := range sourceOffers {
			if !seenTargets[target] {
				seenTargets[target] = true
				candidates = append(candidates, target)
			}
		}
	}
	slices.SortFunc(candidates, compareWidestFirst)
	return candidates
}

func (offers offerBook) bestSource(engineName string, target Target, guardedSources map[string]bool) (string, time.Duration) {
	chosenSource := ""
	chosenRemaining := time.Duration(0)
	for sourceName, sourceOffers := range offers {
		remaining, offered := sourceOffers[target]
		if !offered || sourceName == engineName || guardedSources[sourceName] {
			continue
		}
		isLonger := remaining > chosenRemaining
		isTieSortingFirst := remaining == chosenRemaining && sourceName < chosenSource
		if chosenSource == "" || isLonger || isTieSortingFirst {
			chosenSource = sourceName
			chosenRemaining = remaining
		}
	}
	return chosenSource, chosenRemaining
}
