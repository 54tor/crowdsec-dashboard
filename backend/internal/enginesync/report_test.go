package enginesync

import "testing"

// A run-level failure (cancel, deadline, panic) concerns every engine of the run: each engine row
// without a code of its own must carry it, otherwise the page shows them "ok".
func TestFinishCopiesTheRunErrorCodeOntoEnginesWithoutOne(testContext *testing.T) {
	report := newReport(runnerTime, false)
	report.engine("alpha")
	report.engine("beta").ErrorCode = ErrorCodeEngineBackoff
	report.ErrorCode = ErrorCodeRunDeadline

	finishedReport := report.finish(runnerTime)

	alphaReport := finishedReport.PerEngine["alpha"]
	if alphaReport.ErrorCode != ErrorCodeRunDeadline || alphaReport.Status != StatusFailed {
		testContext.Errorf("alpha must inherit the run code and fail, got %+v", alphaReport)
	}
	if finishedReport.PerEngine["beta"].ErrorCode != ErrorCodeEngineBackoff {
		testContext.Errorf("beta keeps its own code, got %+v", finishedReport.PerEngine["beta"])
	}
}

func TestFinishLeavesEnginesUntouchedWithoutRunErrorCode(testContext *testing.T) {
	report := newReport(runnerTime, false)
	report.engine("alpha")

	finishedReport := report.finish(runnerTime)

	if alphaReport := finishedReport.PerEngine["alpha"]; alphaReport.ErrorCode != "" || alphaReport.Status != StatusOK {
		testContext.Errorf("alpha must stay ok without a run code, got %+v", alphaReport)
	}
}
