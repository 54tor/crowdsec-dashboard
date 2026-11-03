package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/enginesync"
)

const maxSyncRunBodyBytes = 1024

type SyncService interface {
	Run(ctx context.Context, options enginesync.RunOptions) (enginesync.Report, error)
	Status() enginesync.Status
}

type syncRunRequest struct {
	ExpectedChanges map[string]int `json:"expected_changes"`
}

type syncHandlers struct {
	service      SyncService
	engines      EngineService
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
	enabled      bool
	dryRun       bool
	interval     time.Duration
}

func newSyncHandlers(loadedConfig config.Config, services Services) syncHandlers {
	return syncHandlers{
		service:      services.Sync,
		engines:      services.Engines,
		recorder:     services.Audit,
		trustedCIDRs: loadedConfig.TrustedProxyCIDRs,
		enabled:      loadedConfig.SyncEnabled,
		dryRun:       loadedConfig.SyncDryRun,
		interval:     loadedConfig.SyncInterval,
	}
}

func (handlers syncHandlers) status(responseWriter http.ResponseWriter, request *http.Request) {
	engineList, listError := handlers.engines.List(request.Context())
	if listError != nil {
		writeEngineError(responseWriter, "list sync engines", listError)
		return
	}
	runnerStatus := handlers.service.Status()
	view := syncStatusView{
		Enabled:         handlers.enabled,
		DryRun:          handlers.dryRun,
		IntervalSeconds: int64(handlers.interval / time.Second),
		Running:         runnerStatus.Running,
		Peers:           neverRunPeerViews(engineList),
		LastPlan:        []syncPlanEntryView{},
	}
	if runnerStatus.LastReport != nil {
		view.Peers = reportPeerViews(*runnerStatus.LastReport, hostsByEngineName(engineList))
		view.LastPlan = planEntryViews(runnerStatus.LastReport.Entries)
	}
	writeJSON(responseWriter, http.StatusOK, view)
}

func (handlers syncHandlers) run(responseWriter http.ResponseWriter, request *http.Request) {
	var payload syncRunRequest
	decodeError := decodeSingleObject(http.MaxBytesReader(responseWriter, request.Body, maxSyncRunBodyBytes), &payload)
	if decodeError != nil && !errors.Is(decodeError, io.EOF) {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if !handlers.enabled {
		writeError(responseWriter, http.StatusConflict, "sync_disabled")
		return
	}
	report, runError := handlers.service.Run(request.Context(), enginesync.RunOptions{ApplyEvenIfGuarded: payload.ExpectedChanges})
	switch {
	case errors.Is(runError, enginesync.ErrOperationRunning):
		writeError(responseWriter, http.StatusConflict, "operation_running")
		return
	case errors.Is(runError, enginesync.ErrRunPanicked):
		handlers.record(request, report)
		writeError(responseWriter, http.StatusInternalServerError, enginesync.ErrorCodeRunPanicked)
		return
	}
	handlers.record(request, report)
	writeJSON(responseWriter, http.StatusOK, syncRunView{
		DryRun:    report.DryRun,
		ErrorCode: report.ErrorCode,
		Peers:     reportPeerViews(report, handlers.engineHosts(request.Context())),
	})
}

func (handlers syncHandlers) engineHosts(ctx context.Context) map[string]string {
	engineList, listError := handlers.engines.List(ctx)
	if listError != nil {
		return map[string]string{}
	}
	return hostsByEngineName(engineList)
}

func (handlers syncHandlers) record(request *http.Request, report enginesync.Report) {
	identity, _ := auth.IdentityFromContext(request.Context())
	clientIP := auditClientIP(request, handlers.trustedCIDRs)
	audit.RecordOrLog(context.WithoutCancel(request.Context()), handlers.recorder, identity.AccountID, audit.ActionSyncRun, SyncRunAuditTarget(report), clientIP)
}

func SyncRunAuditTarget(report enginesync.Report) string {
	added, removed, skipped := 0, 0, 0
	for _, engineReport := range report.PerEngine {
		added += engineReport.Added
		removed += engineReport.Removed
		skipped += totalSkipped(engineReport.Skipped)
	}
	return fmt.Sprintf("engines=%d added=%d removed=%d skipped=%d dry_run=%t", len(report.PerEngine), added, removed, skipped, report.DryRun)
}
