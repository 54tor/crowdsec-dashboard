package enginesync

import "sync"

type Status struct {
	Running    bool
	LastReport *Report
}

type statusTracker struct {
	mutex      sync.Mutex
	running    bool
	lastReport *Report
}

func (tracker *statusTracker) start() {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	tracker.running = true
}

func (tracker *statusTracker) finish(report Report) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	tracker.running = false
	storedReport := report.clone()
	tracker.lastReport = &storedReport
}

func (tracker *statusTracker) snapshot() Status {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	status := Status{Running: tracker.running}
	if tracker.lastReport != nil {
		reportCopy := tracker.lastReport.clone()
		status.LastReport = &reportCopy
	}
	return status
}
