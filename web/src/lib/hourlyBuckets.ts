import type { Alert } from '@/api/types'

export interface HourBucket {
  hourStart: number
  count: number
}

function startOfHour(timestamp: number): number {
  const hourStart = new Date(timestamp)
  hourStart.setMinutes(0, 0, 0)
  return hourStart.getTime()
}

export function bucketAlertsPerHour(alerts: Alert[]): HourBucket[] {
  const countsByHour = new Map<number, number>()
  for (const alertRow of alerts) {
    const createdTime = new Date(alertRow.created_at).getTime()
    if (Number.isNaN(createdTime)) {
      continue
    }
    const hourStart = startOfHour(createdTime)
    countsByHour.set(hourStart, (countsByHour.get(hourStart) ?? 0) + 1)
  }
  return [...countsByHour.entries()]
    .map(([hourStart, count]) => ({ hourStart, count }))
    .sort((earlier, later) => earlier.hourStart - later.hourStart)
}
