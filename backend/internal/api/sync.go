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

const (
	maxSyncRunBodyBytes = 1024
	syncAuditTimeout    = 5 * time.Second
)

type SyncService interface {
	StartBackground(ctx context.Context, options enginesync.RunOptions, onFinished func(enginesync.Report, error)) error
	Status() enginesync.Status
}

type syncRunRequest struct {
	ExpectedChanges map[string]int `json:"expected_changes"`
}

type syncHandlers struct {
	lifecycle    context.Context
	service      SyncService
	engines      EngineService
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
	enabled      bool
	dryRun       bool
	interval     time.Duration
}

func newSyncHandlers(loadedConfig config.Config, services Services) syncHandlers {
	lifecycle := services.LifecycleContext
	if lifecycle == nil {
		lifecycle = context.Background()
	}
	return syncHandlers{
		lifecycle:    lifecycle,
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
	identity, _ := auth.IdentityFromContext(request.Context())
	clientIP := auditClientIP(request, handlers.trustedCIDRs)
	recordFinishedRun := func(report enginesync.Report, _ error) {
		handlers.record(identity.AccountID, clientIP, report)
	}
	options := enginesync.RunOptions{ApplyEvenIfGuarded: payload.ExpectedChanges}
	if startError := handlers.service.StartBackground(handlers.lifecycle, options, recordFinishedRun); startError != nil {
		writeError(responseWriter, http.StatusConflict, "operation_running")
		return
	}
	writeJSON(responseWriter, http.StatusAccepted, map[string]string{"status": "started"})
}

func (handlers syncHandlers) record(accountID int64, clientIP string, report enginesync.Report) {
	auditContext, cancelAudit := context.WithTimeout(context.Background(), syncAuditTimeout)
	defer cancelAudit()
	audit.RecordOrLog(auditContext, handlers.recorder, accountID, audit.ActionSyncRun, SyncRunAuditTarget(report), clientIP)
}

func SyncRunAuditTarget(report enginesync.Report) string {
	added, removed, skipped := 0, 0, 0
	for _, engineReport := range report.PerEngine {
		added += engineReport.Added
		removed += engineReport.Removed
		skipped += totalSkipped(engineReport.Skipped)
	}
	return fmt.Sprintf("dry_run=%t engines=%d added=%d removed=%d skipped=%d", report.DryRun, len(report.PerEngine), added, removed, skipped)
}
