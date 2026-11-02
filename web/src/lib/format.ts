const STALE_AFTER_MINUTES = 5
const MILLISECONDS_PER_MINUTE = 60_000

const RELATIVE_UNITS: { unit: Intl.RelativeTimeFormatUnit; minutes: number }[] = [
  { unit: 'day', minutes: 1440 },
  { unit: 'hour', minutes: 60 },
  { unit: 'minute', minutes: 1 },
]

export function formatDateTime(isoDate: string, language: string): string {
  const parsedDate = new Date(isoDate)
  if (Number.isNaN(parsedDate.getTime())) {
    return isoDate
  }
  return new Intl.DateTimeFormat(language, { dateStyle: 'medium', timeStyle: 'medium' }).format(parsedDate)
}

export function minutesSince(isoDate: string, now: number): number | null {
  const parsedTime = new Date(isoDate).getTime()
  if (Number.isNaN(parsedTime)) {
    return null
  }
  return Math.max(0, (now - parsedTime) / MILLISECONDS_PER_MINUTE)
}

export function isStale(isoDate: string | null, now: number): boolean {
  if (isoDate === null) {
    return true
  }
  const elapsedMinutes = minutesSince(isoDate, now)
  return elapsedMinutes === null || elapsedMinutes > STALE_AFTER_MINUTES
}

export function formatRelativeAge(isoDate: string, now: number, language: string): string {
  const elapsedMinutes = minutesSince(isoDate, now)
  if (elapsedMinutes === null) {
    return isoDate
  }
  const formatter = new Intl.RelativeTimeFormat(language, { numeric: 'auto' })
  const matchingUnit = RELATIVE_UNITS.find((candidate) => elapsedMinutes >= candidate.minutes)
  if (!matchingUnit) {
    return formatter.format(0, 'minute')
  }
  return formatter.format(-Math.floor(elapsedMinutes / matchingUnit.minutes), matchingUnit.unit)
}

export function formatNumber(value: number, language: string): string {
  return new Intl.NumberFormat(language).format(value)
}

const DURATION_UNITS: { unit: 'day' | 'hour' | 'minute' | 'second'; seconds: number; minimumSeconds: number }[] = [
  { unit: 'day', seconds: 86_400, minimumSeconds: 172_800 },
  { unit: 'hour', seconds: 3_600, minimumSeconds: 3_600 },
  { unit: 'minute', seconds: 60, minimumSeconds: 60 },
  { unit: 'second', seconds: 1, minimumSeconds: 0 },
]

export function formatDuration(totalSeconds: number, language: string): string {
  const matchingUnit = DURATION_UNITS.find((candidate) => totalSeconds >= candidate.minimumSeconds) ?? DURATION_UNITS[DURATION_UNITS.length - 1]
  return new Intl.NumberFormat(language, {
    style: 'unit',
    unit: matchingUnit.unit,
    unitDisplay: 'narrow',
    maximumFractionDigits: 1,
  }).format(totalSeconds / matchingUnit.seconds)
}
