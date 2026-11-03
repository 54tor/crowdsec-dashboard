package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"crowdsec-dashboard/internal/confwrite"
)

const (
	ReasonForbiddenName           = "forbidden_name"
	ReasonForbiddenSource         = "forbidden_source"
	ReasonRedactedContent         = "redacted_content"
	ReasonInvalidYAML             = "invalid_yaml"
	ReasonFileTooLarge            = "too_large"
	ReasonNotRegularFile          = "not_regular_file"
	ReasonUnchanged               = "unchanged"
	ErrorCodeImportDisabled       = "import_disabled"
	ErrorCodeImportDirUnavailable = "section_unavailable"
	ErrorCodeConfigTestFailed     = "config_test_failed"
	ErrorCodeConfigInconsistent   = "config_inconsistent"
	FileCreated                   = "created"
	FileUpdated                   = "updated"
	FileUnchanged                 = "unchanged"
	acquisitionDirPrefix          = "acquis.d/"
	rejectedFilePrefix            = "file#"
)

var (
	ErrConfigTestFailed   = confwrite.ErrConfigTestFailed
	ErrConfigInconsistent = confwrite.ErrConfigInconsistent
)

var displayableFileName = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)

var configSkipReasons = []struct {
	failure error
	reason  string
}{
	{confwrite.ErrInvalidName, ReasonInvalidName},
	{confwrite.ErrForbiddenName, ReasonForbiddenName},
	{confwrite.ErrTooLarge, ReasonFileTooLarge},
	{confwrite.ErrRedactedContent, ReasonRedactedContent},
	{confwrite.ErrInvalidYAML, ReasonInvalidYAML},
	{confwrite.ErrForbiddenSource, ReasonForbiddenSource},
	{confwrite.ErrNotRegularFile, ReasonNotRegularFile},
}

type configImport struct{}

func (configImport) Plan(_ context.Context, deps ImportDeps, imported Bundle) (SectionPlan, error) {
	if !deps.ConfigImportEnabled {
		return SectionPlan{Unavailable: true, UnavailableCode: ErrorCodeImportDisabled}, nil
	}
	if deps.TestConfig == nil || confwrite.CheckWritable(deps.ConfigImportDir) != nil {
		return SectionPlan{Unavailable: true, UnavailableCode: ErrorCodeImportDirUnavailable}, nil
	}
	sectionPlan := SectionPlan{}
	plannedNames := map[string]bool{}
	for fileIndex, configFile := range imported.Sections.Config.Files {
		if planError := sectionPlan.planConfigFile(deps.ConfigImportDir, fileIndex, configFile, plannedNames); planError != nil {
			return SectionPlan{Unavailable: true, UnavailableCode: ErrorCodeImportDirUnavailable}, nil
		}
	}
	slices.SortFunc(sectionPlan.Config, func(first, second FileAction) int { return strings.Compare(first.Name, second.Name) })
	return sectionPlan, nil
}

func (sectionPlan *SectionPlan) planConfigFile(importDir string, fileIndex int, configFile ConfigFile, plannedNames map[string]bool) error {
	fileName, isAcquisition := strings.CutPrefix(configFile.Name, acquisitionDirPrefix)
	if !isAcquisition {
		sectionPlan.skip(SectionConfig, displayName(configFile.Name, fileIndex), ReasonForbiddenName)
		return nil
	}
	if nameError := confwrite.ValidateName(fileName); nameError != nil {
		sectionPlan.skip(SectionConfig, displayName(configFile.Name, fileIndex), configSkipReason(nameError))
		return nil
	}
	if plannedNames[fileName] {
		sectionPlan.skip(SectionConfig, fileName, ReasonDuplicate)
		return nil
	}
	plannedNames[fileName] = true
	content := []byte(configFile.Content)
	if contentError := confwrite.ValidateContent(content); contentError != nil {
		sectionPlan.skip(SectionConfig, fileName, configSkipReason(contentError))
		return nil
	}
	current, readError := confwrite.ReadCurrent(importDir, fileName)
	if errors.Is(readError, confwrite.ErrNotRegularFile) {
		sectionPlan.skip(SectionConfig, fileName, ReasonNotRegularFile)
		return nil
	}
	if readError != nil {
		return readError
	}
	sectionPlan.Config = append(sectionPlan.Config, newFileAction(fileName, content, current))
	return nil
}

func newFileAction(fileName string, content []byte, current confwrite.Current) FileAction {
	action := FileAction{Name: fileName, Change: FileCreated, SHA256: contentHash(content), content: content}
	if current.Exists {
		action.Change = FileUpdated
		if !current.Oversized {
			action.PreviousSHA256 = contentHash(current.Content)
		}
	}
	if action.PreviousSHA256 == action.SHA256 {
		action.Change = FileUnchanged
		return action
	}
	action.Diff, action.DiffTruncated = boundedDiff(current.Content, content)
	action.DiffTruncated = action.DiffTruncated || current.Oversized
	return action
}

func contentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func displayName(name string, fileIndex int) string {
	if displayableFileName.MatchString(name) && !strings.Contains(name, "..") {
		return name
	}
	return rejectedFilePrefix + strconv.Itoa(fileIndex)
}

func configSkipReason(failure error) string {
	for _, candidate := range configSkipReasons {
		if errors.Is(failure, candidate.failure) {
			return candidate.reason
		}
	}
	return ReasonInvalid
}

func (configImport) Apply(ctx context.Context, deps ImportDeps, sectionPlan SectionPlan) (SectionReport, error) {
	report := newSectionReport(sectionPlan)
	changes := make([]confwrite.FileChange, 0, len(sectionPlan.Config))
	for _, fileAction := range sectionPlan.Config {
		changes = append(changes, confwrite.FileChange{Name: fileAction.Name, Content: fileAction.content})
	}
	runConfigTest := func(context.Context) error { return deps.TestConfig(ctx) }
	result, applyError := confwrite.Apply(deps.ConfigImportDir, changes, runConfigTest)
	for range result.Unchanged {
		report.skip(ReasonUnchanged)
	}
	writtenCount := len(result.Created) + len(result.Updated)
	if applyError != nil {
		report.Failed = writtenCount
		var inconsistentError *confwrite.InconsistentError
		if errors.As(applyError, &inconsistentError) {
			report.AffectedFiles = inconsistentError.Files
		}
		return report, applyError
	}
	report.Applied = writtenCount
	return report, nil
}
