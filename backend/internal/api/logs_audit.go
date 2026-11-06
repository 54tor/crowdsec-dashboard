package api

import (
	"context"
	"net/http"
	"path"
	"sync"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
)

const viewAuditIdleWindow = 2 * time.Minute

type viewKey struct {
	engineName string
	sourceID   string
}

type viewState struct {
	key        viewKey
	lastAccess time.Time
}

type viewAuditGate struct {
	mutex    sync.Mutex
	now      func() time.Time
	statuses map[int64]viewState
}

func newViewAuditGate(now func() time.Time) *viewAuditGate {
	return &viewAuditGate{now: now, statuses: map[int64]viewState{}}
}

func (gate *viewAuditGate) shouldRecord(accountID int64, engineName, sourceID string) bool {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	currentTime := gate.now()
	gate.forgetIdleAccounts(currentTime)
	previous, hasPrevious := gate.statuses[accountID]
	key := viewKey{engineName: engineName, sourceID: sourceID}
	gate.statuses[accountID] = viewState{key: key, lastAccess: currentTime}
	return !hasPrevious || previous.key != key
}

func (gate *viewAuditGate) forgetIdleAccounts(currentTime time.Time) {
	for accountID, statusCourant := range gate.statuses {
		if currentTime.Sub(statusCourant.lastAccess) > viewAuditIdleWindow {
			delete(gate.statuses, accountID)
		}
	}
}

func (handlers logHandlers) recordView(request *http.Request, engineName string, sources LogSources, sourceID string) {
	identity, _ := auth.IdentityFromContext(request.Context())
	if !handlers.gate.shouldRecord(identity.AccountID, engineName, sourceID) {
		return
	}
	auditContext, cancelAudit := context.WithTimeout(context.WithoutCancel(request.Context()), engineAuditTimeout)
	defer cancelAudit()
	target := abbreviatedPair(engineName, path.Base(sourceLabelOf(auditContext, sources, sourceID)), audit.MaximumTargetRunes)
	audit.RecordOrLog(auditContext, handlers.recorder, identity.AccountID, audit.ActionLogsViewed, target, auditClientIP(request, handlers.trustedCIDRs))
}

func sourceLabelOf(ctx context.Context, sources LogSources, sourceID string) string {
	listing, listError := sources.List(ctx)
	if listError != nil {
		return sourceID
	}
	for _, sourceCourante := range listing.Sources {
		if sourceCourante.ID == sourceID {
			return sourceCourante.Label
		}
	}
	return sourceID
}
