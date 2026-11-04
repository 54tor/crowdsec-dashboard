import type { Alert } from '@/api/types'

export type AlertStatus = 'simulated' | 'activeBan' | 'report'

export function alertStatusOf(alertRow: Pick<Alert, 'simulated' | 'decisions'>): AlertStatus {
  if (alertRow.simulated) {
    return 'simulated'
  }
  const hasDecision = alertRow.decisions.length > 0
  return hasDecision ? 'activeBan' : 'report'
}
