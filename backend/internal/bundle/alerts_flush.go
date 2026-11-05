package bundle

const (
	flushSafetyPercent     = 90
	maxLocalAlertsRead     = 20000
	maxLocalAlertsReadSize = 2 * MaxBytes
)

func flushThreshold(maxItems int) int {
	return maxItems * flushSafetyPercent / 100
}
