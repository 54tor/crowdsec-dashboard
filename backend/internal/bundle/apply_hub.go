package bundle

import (
	"context"
	"slices"
	"strings"

	"crowdsec-dashboard/internal/cscli"
)

const versionMismatchWarning = "version_mismatch:"

type hubImport struct{}

func (hubImport) Plan(ctx context.Context, deps ImportDeps, imported Bundle) (SectionPlan, error) {
	if deps.ReadHub == nil || deps.InstallCollection == nil {
		return SectionPlan{Unavailable: true}, nil
	}
	items, readError := deps.ReadHub(ctx)
	if readError != nil {
		return SectionPlan{Unavailable: true}, nil
	}
	installedVersions := installedCollectionVersions(items)
	sectionPlan := SectionPlan{}
	plannedNames := map[string]bool{}
	for _, collection := range imported.Sections.Hub.Collections {
		sectionPlan.planCollection(collection, installedVersions, plannedNames)
	}
	if len(sectionPlan.Hub) > MaxImportedCollections {
		return SectionPlan{}, ErrTooManyChanges
	}
	return sectionPlan, nil
}

func installedCollectionVersions(items []HubItem) map[string]string {
	installedVersions := map[string]string{}
	for _, item := range items {
		isEnabled := slices.Contains(strings.Split(item.Status, ","), hubStatusEnabled)
		if item.Type == hubCollectionType && isEnabled {
			installedVersions[item.Name] = item.Version
		}
	}
	return installedVersions
}

func (sectionPlan *SectionPlan) planCollection(collection HubCollection, installedVersions map[string]string, plannedNames map[string]bool) {
	if cscli.ValidateHubName(collection.Name) != nil {
		sectionPlan.skip(SectionHub, collection.Name, ReasonInvalidName)
		return
	}
	if plannedNames[collection.Name] {
		sectionPlan.skip(SectionHub, collection.Name, ReasonDuplicate)
		return
	}
	plannedNames[collection.Name] = true
	installedVersion, isInstalled := installedVersions[collection.Name]
	if !isInstalled {
		sectionPlan.Hub = append(sectionPlan.Hub, HubAction(collection))
		return
	}
	sectionPlan.skip(SectionHub, collection.Name, ReasonAlreadyInstalled)
	isVersionMismatch := collection.Version != "" && installedVersion != "" && collection.Version != installedVersion
	if isVersionMismatch {
		sectionPlan.Warnings = append(sectionPlan.Warnings, versionMismatchWarning+collection.Name)
	}
}

func (sectionPlan *SectionPlan) skip(sectionName, target, reason string) {
	sectionPlan.Skipped = append(sectionPlan.Skipped, SkippedItem{Section: sectionName, Target: target, Reason: reason})
}

func (hubImport) Apply(ctx context.Context, deps ImportDeps, sectionPlan SectionPlan) (SectionReport, error) {
	report := newSectionReport(sectionPlan)
	for _, hubAction := range sectionPlan.Hub {
		if installError := deps.InstallCollection(ctx, hubAction.Name); installError != nil {
			report.Failed++
			return report, installError
		}
		report.Applied++
	}
	return report, nil
}
