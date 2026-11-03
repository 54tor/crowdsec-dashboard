package enginesync

import (
	"slices"

	"crowdsec-dashboard/internal/allowguard"
)

const (
	BlockedSourceGuard = "source_guard"
	BlockedTargetGuard = "target_guard"
)

func sourcesOverLimit(changes []Change, maxChanges int, guardedSources map[string]bool) []string {
	changesPerSource := map[string]int{}
	for _, change := range changes {
		changesPerSource[change.Source]++
	}
	var overLimit []string
	for sourceName, changeCount := range changesPerSource {
		if changeCount > maxChanges && !guardedSources[sourceName] {
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
		if changeCount > maxChanges {
			addBlockReason(blocked, engineName, BlockedTargetGuard)
		}
	}
	return slices.DeleteFunc(changes, func(change Change) bool {
		return changesPerEngine[change.Engine] > maxChanges
	})
}

func blockUnreadableAllowlists(classifiedSnapshots []classifiedSnapshot, blocked map[string]string) {
	for _, snapshot := range classifiedSnapshots {
		if !snapshot.Allowlist.Available() {
			addBlockReason(blocked, snapshot.Engine, allowguard.ReasonAllowlistUnavailable)
		}
	}
}

func addBlockReason(blocked map[string]string, engineName string, reason string) {
	if existingReason, alreadyBlocked := blocked[engineName]; alreadyBlocked {
		blocked[engineName] = existingReason + "," + reason
	} else {
		blocked[engineName] = reason
	}
}
