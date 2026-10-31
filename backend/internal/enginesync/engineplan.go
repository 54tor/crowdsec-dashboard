package enginesync

import (
	"cmp"
	"slices"
)

type copyKey struct {
	source string
	target Target
}

func planEngine(targetSnapshot classifiedSnapshot, offers offerBook, guardedSources map[string]bool, rules Rules) ([]Change, []Skip) {
	copyChanges, keptCopies := reconcileCopies(targetSnapshot, offers, guardedSources, rules)
	coverage := coverageIndex{}
	exactCopies := map[Target]bool{}
	for _, localBan := range targetSnapshot.natives {
		if localBan.isActive() {
			coverage.add(localBan.Target)
		}
	}
	for _, keptCopy := range keptCopies {
		coverage.add(keptCopy.Target)
		exactCopies[keptCopy.Target] = true
	}
	addChanges, skips := planAdds(targetSnapshot.Engine, offers, guardedSources, coverage, exactCopies)
	return append(copyChanges, addChanges...), skips
}

func planAdds(engineName string, offers offerBook, guardedSources map[string]bool, coverage coverageIndex, exactCopies map[Target]bool) ([]Change, []Skip) {
	var changes []Change
	var skips []Skip
	for _, candidate := range offers.candidatesFor(engineName, guardedSources) {
		if exactCopies[candidate] {
			continue
		}
		if coverage.covers(candidate) {
			skips = append(skips, Skip{Engine: engineName, Target: candidate, Reason: ReasonCovered})
			continue
		}
		sourceName, remaining := offers.firstSource(engineName, candidate, guardedSources)
		changes = append(changes, Change{Engine: engineName, Kind: ChangeAdd, Target: candidate, Source: sourceName, Remaining: remaining})
		coverage.add(candidate)
	}
	return changes, skips
}

func reconcileCopies(targetSnapshot classifiedSnapshot, offers offerBook, guardedSources map[string]bool, rules Rules) ([]Change, []Ban) {
	var changes []Change
	var keptCopies []Ban
	for _, copyGroup := range groupCopies(targetSnapshot.copies) {
		sourceName := copySource(copyGroup[0])
		if guardedSources[sourceName] {
			keptCopies = append(keptCopies, copyGroup...)
			continue
		}
		keeper := copyGroup[0]
		for _, duplicateCopy := range copyGroup[1:] {
			changes = append(changes, removal(targetSnapshot.Engine, duplicateCopy))
		}
		change, keep := reconcileCopy(targetSnapshot.Engine, keeper, offers, rules)
		if change != nil {
			changes = append(changes, *change)
		}
		if keep {
			keptCopies = append(keptCopies, keeper)
		}
	}
	return changes, keptCopies
}

func reconcileCopy(engineName string, existingCopy Ban, offers offerBook, rules Rules) (*Change, bool) {
	sourceName := copySource(existingCopy)
	if !existingCopy.isActive() || targetRefusal(existingCopy.Target, rules) != "" {
		return new(removal(engineName, existingCopy)), false
	}
	if len(rules.KnownEngines) > 0 && !rules.KnownEngines[sourceName] {
		return new(removal(engineName, existingCopy)), false
	}
	if !offers.isComplete(sourceName) {
		return nil, true
	}
	sourceRemaining, offered := offers.remaining(sourceName, existingCopy.Target)
	if !offered {
		return new(removal(engineName, existingCopy)), false
	}
	if sourceRemaining-existingCopy.Remaining > rules.ExtendThreshold {
		return &Change{Engine: engineName, Kind: ChangeReplace, Target: existingCopy.Target, Source: sourceName, Remaining: sourceRemaining, DecisionID: existingCopy.ID}, true
	}
	return nil, true
}

func removal(engineName string, existingCopy Ban) Change {
	return Change{Engine: engineName, Kind: ChangeRemove, Target: existingCopy.Target, Source: copySource(existingCopy), DecisionID: existingCopy.ID}
}

func groupCopies(copies []Ban) [][]Ban {
	groupsByKey := map[copyKey][]Ban{}
	var keys []copyKey
	for _, existingCopy := range copies {
		key := copyKey{source: copySource(existingCopy), target: existingCopy.Target}
		if _, known := groupsByKey[key]; !known {
			keys = append(keys, key)
		}
		groupsByKey[key] = append(groupsByKey[key], existingCopy)
	}
	groups := make([][]Ban, 0, len(keys))
	for _, key := range keys {
		group := groupsByKey[key]
		slices.SortFunc(group, func(first, second Ban) int {
			return cmp.Or(cmp.Compare(second.Remaining, first.Remaining), cmp.Compare(first.ID, second.ID))
		})
		groups = append(groups, group)
	}
	return groups
}
