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

type viewAuditGate struct {
	mutex    sync.Mutex
	now      func() time.Time
	accesses map[int64]map[viewKey]time.Time
}

func newViewAuditGate(now func() time.Time) *viewAuditGate {
	return &viewAuditGate{now: now, accesses: map[int64]map[viewKey]time.Time{}}
}

func (gate *viewAuditGate) shouldRecord(accountID int64, engineName, sourceID string) bool {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	currentTime := gate.now()
	gate.forgetIdleViews(currentTime)
	key := viewKey{engineName: engineName, sourceID: sourceID}
	if gate.accesses[accountID] == nil {
		gate.accesses[accountID] = map[viewKey]time.Time{}
	}
	_, isOpenView := gate.accesses[accountID][key]
	gate.accesses[accountID][key] = currentTime
	return !isOpenView
}

func (gate *viewAuditGate) forgetIdleViews(currentTime time.Time) {
	for accountID, views := range gate.accesses {
		for key, lastAccess := range views {
			if currentTime.Sub(lastAccess) > viewAuditIdleWindow {
				delete(views, key)
			}
		}
		if len(views) == 0 {
			delete(gate.accesses, accountID)
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
