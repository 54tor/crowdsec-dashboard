package enginesync

import (
	"cmp"
	"slices"
	"strings"

	"crowdsec-dashboard/internal/allowguard"
)

func planEngine(targetSnapshot classifiedSnapshot, offers offerBook, guardedSources map[string]bool, rules Rules) ([]Change, []Skip) {
	copyChanges, keptCopies := reconcileCopies(targetSnapshot, offers, guardedSources, rules)
	coverage := make(coverageIndex, len(targetSnapshot.Bans))
	exactCopies := make(map[Target]bool, len(keptCopies))
	for _, localBan := range targetSnapshot.natives {
		if localBan.isActive() {
			coverage.add(localBan.Target)
		}
	}
	for _, keptCopy := range keptCopies {
		coverage.add(keptCopy.Target)
		exactCopies[keptCopy.Target] = true
	}
	addChanges, skips := planAdds(targetSnapshot.Engine, targetSnapshot.Allowlist, offers, guardedSources, coverage, exactCopies)
	return append(copyChanges, addChanges...), skips
}

func planAdds(engineName string, allowlist allowguard.Guard, offers offerBook, guardedSources map[string]bool, coverage coverageIndex, exactCopies map[Target]bool) ([]Change, []Skip) {
	var changes []Change
	var skips []Skip
	for _, candidate := range offers.candidatesFor(engineName, guardedSources) {
		if exactCopies[candidate] {
			continue
		}
		if verdict := allowlist.Check(candidate.Prefix); !verdict.Allowed {
			skips = append(skips, Skip{Engine: engineName, Target: candidate, Reason: verdict.Reason})
			continue
		}
		if coverage.covers(candidate) {
			skips = append(skips, Skip{Engine: engineName, Target: candidate, Reason: ReasonCovered})
			continue
		}
		sourceName, remaining := offers.bestSource(engineName, candidate, guardedSources)
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
			guardedChanges, guardedKept := reconcileGuardedCopies(targetSnapshot.Engine, targetSnapshot.Allowlist, copyGroup)
			changes = append(changes, guardedChanges...)
			keptCopies = append(keptCopies, guardedKept...)
			continue
		}
		keeper := copyGroup[0]
		for _, duplicateCopy := range copyGroup[1:] {
			changes = append(changes, removal(targetSnapshot.Engine, duplicateCopy))
		}
		change, keep := reconcileCopy(targetSnapshot.Engine, targetSnapshot.Allowlist, keeper, offers, rules)
		if change != nil {
			changes = append(changes, *change)
		}
		if keep {
			keptCopies = append(keptCopies, keeper)
		}
	}
	return changes, keptCopies
}

func reconcileCopy(engineName string, allowlist allowguard.Guard, existingCopy Ban, offers offerBook, rules Rules) (*Change, bool) {
	sourceName := copySource(existingCopy)
	isRefusedByTarget := targetRefusal(existingCopy.Target, rules) != "" || !allowlist.Check(existingCopy.Target.Prefix).Allowed
	if sourceName == engineName || !existingCopy.isActive() || isRefusedByTarget {
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

func reconcileGuardedCopies(engineName string, allowlist allowguard.Guard, copyGroup []Ban) ([]Change, []Ban) {
	if allowlist.Check(copyGroup[0].Target.Prefix).Allowed {
		return nil, activeCopies(copyGroup)
	}
	changes := make([]Change, 0, len(copyGroup))
	for _, refusedCopy := range copyGroup {
		changes = append(changes, removal(engineName, refusedCopy))
	}
	return changes, nil
}

func activeCopies(copyGroup []Ban) []Ban {
	var active []Ban
	for _, existingCopy := range copyGroup {
		if existingCopy.isActive() {
			active = append(active, existingCopy)
		}
	}
	return active
}

func removal(engineName string, existingCopy Ban) Change {
	return Change{Engine: engineName, Kind: ChangeRemove, Target: existingCopy.Target, Source: copySource(existingCopy), DecisionID: existingCopy.ID}
}

func groupCopies(copies []Ban) [][]Ban {
	sortedCopies := slices.Clone(copies)
	slices.SortFunc(sortedCopies, func(first, second Ban) int {
		return cmp.Or(
			strings.Compare(first.Scenario, second.Scenario),
			compareTargets(first.Target, second.Target),
			cmp.Compare(second.Remaining, first.Remaining),
			cmp.Compare(first.ID, second.ID),
		)
	})
	groups := make([][]Ban, 0, len(sortedCopies))
	groupStart := 0
	for copyIndex := 1; copyIndex <= len(sortedCopies); copyIndex++ {
		isGroupEnd := copyIndex == len(sortedCopies) || !sameCopyKey(sortedCopies[groupStart], sortedCopies[copyIndex])
		if isGroupEnd {
			groups = append(groups, sortedCopies[groupStart:copyIndex])
			groupStart = copyIndex
		}
	}
	return groups
}

func sameCopyKey(first, second Ban) bool {
	return first.Scenario == second.Scenario && first.Target == second.Target
}
