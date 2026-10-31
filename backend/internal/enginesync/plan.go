package enginesync

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"
)

type ChangeKind string

const (
	ChangeAdd     ChangeKind = "add"
	ChangeRemove  ChangeKind = "remove"
	ChangeReplace ChangeKind = "replace"
)

type Change struct {
	Engine     string
	Kind       ChangeKind
	Target     Target
	Source     string
	Remaining  time.Duration
	DecisionID int64
}

type Skip struct {
	Engine string
	Target Target
	Reason string
}

type Plan struct {
	Changes []Change
	Skipped []Skip
	Blocked map[string]string
}

func BuildPlan(snapshots []Snapshot, rules Rules, now time.Time) Plan {
	classifiedSnapshots := classifyAll(snapshots)
	rules.KnownEngines = knownEnginesWithSnapshots(rules.KnownEngines, classifiedSnapshots)
	offers, shareSkips := collectOffers(classifiedSnapshots, rules)
	guardedSources := map[string]bool{}
	for {
		changes, coverageSkips := planAllEngines(classifiedSnapshots, offers, guardedSources, rules)
		newlyGuarded := sourcesOverLimit(changes, rules.MaxChanges)
		if len(newlyGuarded) == 0 {
			blocked := blockedSources(guardedSources)
			changes = dropBlockedTargets(changes, rules.MaxChanges, blocked)
			return Plan{
				Changes: sortedChanges(changes),
				Skipped: sortedSkips(append(shareSkips, coverageSkips...)),
				Blocked: blocked,
			}
		}
		for _, sourceName := range newlyGuarded {
			guardedSources[sourceName] = true
		}
	}
}

func classifyAll(snapshots []Snapshot) []classifiedSnapshot {
	classifiedSnapshots := make([]classifiedSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		classifiedSnapshots = append(classifiedSnapshots, classify(snapshot))
	}
	slices.SortStableFunc(classifiedSnapshots, func(first, second classifiedSnapshot) int {
		return strings.Compare(first.Engine, second.Engine)
	})
	return classifiedSnapshots
}

func knownEnginesWithSnapshots(configuredEngines map[string]bool, classifiedSnapshots []classifiedSnapshot) map[string]bool {
	if len(configuredEngines) == 0 {
		return configuredEngines
	}
	knownEngines := maps.Clone(configuredEngines)
	for _, snapshot := range classifiedSnapshots {
		knownEngines[snapshot.Engine] = true
	}
	return knownEngines
}

func planAllEngines(classifiedSnapshots []classifiedSnapshot, offers offerBook, guardedSources map[string]bool, rules Rules) ([]Change, []Skip) {
	var changes []Change
	var skips []Skip
	for _, targetSnapshot := range classifiedSnapshots {
		if targetSnapshot.State != ReadComplete {
			continue
		}
		engineChanges, engineSkips := planEngine(targetSnapshot, offers, guardedSources, rules)
		changes = append(changes, engineChanges...)
		skips = append(skips, engineSkips...)
	}
	return changes, skips
}

func sortedChanges(changes []Change) []Change {
	slices.SortFunc(changes, func(first, second Change) int {
		return cmp.Or(
			strings.Compare(first.Engine, second.Engine),
			strings.Compare(string(first.Kind), string(second.Kind)),
			compareTargets(first.Target, second.Target),
			strings.Compare(first.Source, second.Source),
			cmp.Compare(first.DecisionID, second.DecisionID),
		)
	})
	return changes
}

func sortedSkips(skips []Skip) []Skip {
	slices.SortFunc(skips, func(first, second Skip) int {
		return cmp.Or(
			strings.Compare(first.Engine, second.Engine),
			compareTargets(first.Target, second.Target),
			strings.Compare(first.Reason, second.Reason),
		)
	})
	return slices.Compact(skips)
}
