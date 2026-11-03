package bundle

import (
	"context"
	"errors"
	"slices"
	"time"
)

var ErrInvalidRequest = errors.New("bundle: invalid export request")

var knownSections = []string{SectionHub, SectionDecision, SectionAlerts, SectionConfig}

type ExportRequest struct {
	Sections       []string
	IncludeSecrets bool
	StripEvents    bool
}

func (request ExportRequest) includes(section string) bool {
	return slices.Contains(request.Sections, section)
}

func (request ExportRequest) validate() error {
	if len(request.Sections) == 0 {
		return ErrInvalidRequest
	}
	for sectionIndex, section := range request.Sections {
		isDuplicate := slices.Contains(request.Sections[:sectionIndex], section)
		if isDuplicate || !slices.Contains(knownSections, section) {
			return ErrInvalidRequest
		}
	}
	return nil
}

func Export(ctx context.Context, deps ExportDeps, request ExportRequest) (Bundle, error) {
	if validationError := request.validate(); validationError != nil {
		return Bundle{}, validationError
	}
	readTime := deps.Now().UTC()
	engineVersion, versionError := deps.EngineVersion(ctx)
	if versionError != nil {
		return Bundle{}, versionError
	}
	exported := Bundle{
		Format:          Format,
		Version:         Version,
		CreatedAt:       readTime,
		EngineVersion:   engineVersion,
		ContainsSecrets: request.IncludeSecrets && request.includes(SectionConfig),
	}
	if sectionsError := exportSections(ctx, deps, request, readTime, &exported.Sections); sectionsError != nil {
		return Bundle{}, sectionsError
	}
	return exported, nil
}

func exportSections(ctx context.Context, deps ExportDeps, request ExportRequest, readTime time.Time, sections *Sections) error {
	var sectionError error
	if request.includes(SectionHub) {
		sections.Hub, sectionError = exportHub(ctx, deps)
		if sectionError != nil {
			return sectionError
		}
	}
	if request.includes(SectionDecision) {
		sections.Decisions, sectionError = exportDecisions(ctx, deps, readTime)
		if sectionError != nil {
			return sectionError
		}
	}
	if request.includes(SectionAlerts) {
		sections.Alerts, sectionError = exportAlerts(ctx, deps, request.StripEvents)
		if sectionError != nil {
			return sectionError
		}
	}
	if request.includes(SectionConfig) {
		sections.Config, sectionError = exportConfig(deps.ConfigDir, request.IncludeSecrets)
	}
	return sectionError
}
