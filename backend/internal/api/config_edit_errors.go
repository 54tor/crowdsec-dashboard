package api

import (
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confschema"
	"crowdsec-dashboard/internal/confwrite"
)

type configEditOutcome struct {
	status int
	code   string
}

var configEditOutcomes = []struct {
	sentinel error
	outcome  configEditOutcome
}{
	{confedit.ErrDigestMismatch, configEditOutcome{http.StatusConflict, "digest_mismatch"}},
	{confedit.ErrSchemaInvalid, configEditOutcome{http.StatusUnprocessableEntity, "schema_invalid"}},
	{confedit.ErrNestingTooDeep, configEditOutcome{http.StatusBadRequest, "invalid_yaml"}},
	{confedit.ErrRedactedWithoutOriginal, configEditOutcome{http.StatusBadRequest, "redacted_content"}},
	{confedit.ErrSecretContextChanged, configEditOutcome{http.StatusBadRequest, "secret_context_changed"}},
	{confedit.ErrMergedStructureChanged, configEditOutcome{http.StatusBadRequest, "merged_structure_changed"}},
	{confwrite.ErrReadOnlyFile, configEditOutcome{http.StatusForbidden, "read_only_file"}},
	{confwrite.ErrProtectedFile, configEditOutcome{http.StatusForbidden, "protected_file"}},
	{confwrite.ErrParentMissing, configEditOutcome{http.StatusNotFound, "parent_missing"}},
	{confwrite.ErrInvalidName, configEditOutcome{http.StatusNotFound, "not_found"}},
	{confwrite.ErrForbiddenName, configEditOutcome{http.StatusNotFound, "not_found"}},
	{confwrite.ErrTooLarge, configEditOutcome{http.StatusRequestEntityTooLarge, "file_too_large"}},
	{confwrite.ErrRedactedContent, configEditOutcome{http.StatusBadRequest, "redacted_content"}},
	{confwrite.ErrInvalidYAML, configEditOutcome{http.StatusBadRequest, "invalid_yaml"}},
	{confwrite.ErrForbiddenSource, configEditOutcome{http.StatusBadRequest, "forbidden_source"}},
	{confwrite.ErrNotRegularFile, configEditOutcome{http.StatusConflict, "not_regular_file"}},
	{confwrite.ErrConfigTestFailed, configEditOutcome{http.StatusUnprocessableEntity, "config_test_failed"}},
	{confwrite.ErrConfigInconsistent, configEditOutcome{http.StatusInternalServerError, "config_inconsistent"}},
	{confwrite.ErrConcurrentChange, configEditOutcome{http.StatusConflict, "digest_mismatch"}},
	{confwrite.ErrRecoveryPending, configEditOutcome{http.StatusConflict, "recovery_pending"}},
}

func configEditOutcomeOf(editError error) (configEditOutcome, bool) {
	for _, errorOutcome := range configEditOutcomes {
		if errors.Is(editError, errorOutcome.sentinel) {
			return errorOutcome.outcome, true
		}
	}
	return configEditOutcome{}, false
}

type configEditRefusal struct {
	Error         string      `json:"error"`
	Line          int         `json:"line,omitempty"`
	Issues        []issueView `json:"issues,omitempty"`
	RolledBack    bool        `json:"rolled_back,omitempty"`
	AffectedFiles []string    `json:"affected_files,omitempty"`
}

type configEditFailure struct {
	editError  error
	issues     []confschema.Issue
	rolledBack bool
}

func writeConfigEditError(responseWriter http.ResponseWriter, failure configEditFailure) {
	outcome, isKnown := configEditOutcomeOf(failure.editError)
	if !isKnown {
		writeUnknownConfigEditError(responseWriter, failure.editError)
		return
	}
	refusal := configEditRefusal{Error: outcome.code, Issues: issueViewsOf(failure.issues), RolledBack: failure.rolledBack}
	var mergeError *confedit.MergeError
	if errors.As(failure.editError, &mergeError) {
		refusal.Line = mergeError.Line
	}
	var inconsistentError *confwrite.InconsistentError
	if errors.As(failure.editError, &inconsistentError) {
		refusal.AffectedFiles = inconsistentError.Files
	}
	writeJSON(responseWriter, outcome.status, refusal)
}

func writeUnknownConfigEditError(responseWriter http.ResponseWriter, editError error) {
	if isSidecarTransportError(editError) {
		writeUpstreamError(responseWriter, editError)
		return
	}
	writeError(responseWriter, http.StatusInternalServerError, "config_unavailable")
}

type issueView struct {
	Line     int    `json:"line"`
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
}

func issueViewsOf(issues []confschema.Issue) []issueView {
	views := make([]issueView, 0, len(issues))
	for _, issue := range issues {
		views = append(views, issueView{Line: issue.Line, Path: issue.Path, Severity: issue.Severity, Code: issue.Code})
	}
	return views
}
