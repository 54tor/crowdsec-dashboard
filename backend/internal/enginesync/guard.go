package enginesync

import "slices"

const (
	BlockedSourceGuard = "source_guard"
	BlockedTargetGuard = "target_guard"
)

func sourcesOverLimit(changes []Change, maxChanges int) []string {
	changesPerSource := map[string]int{}
	for _, change := range changes {
		changesPerSource[change.Source]++
	}
	var overLimit []string
	for sourceName, changeCount := range changesPerSource {
		if changeCount > maxChanges {
			overLimit = append(overLimit, sourceName)
		}
	}
	slices.Sort(overLimit)
	return overLimit
}

func blockedSources(guardedSources map[string]bool) map[string]string {
	blocked := make(map[string]string, len(guardedSources))
	for sourceName := range guardedSources {
		blocked[sourceName] = BlockedSourceGuard
	}
	return blocked
}

func dropBlockedTargets(changes []Change, maxChanges int, blocked map[string]string) []Change {
	changesPerEngine := map[string]int{}
	for _, change := range changes {
		changesPerEngine[change.Engine]++
	}
	for engineName, changeCount := range changesPerEngine {
		if changeCount <= maxChanges {
			continue
		}
		if existingReason, alreadyBlocked := blocked[engineName]; alreadyBlocked {
			blocked[engineName] = existingReason + "," + BlockedTargetGuard
		} else {
			blocked[engineName] = BlockedTargetGuard
		}
	}
	return slices.DeleteFunc(changes, func(change Change) bool {
		return changesPerEngine[change.Engine] > maxChanges
	})
}
