import { lazy, Suspense, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Alert } from '@/api/types'
import { Skeleton } from '@/components/ui/skeleton'
import { bucketAlertsPerHour } from '@/lib/hourlyBuckets'
import { formatNumber } from '@/lib/format'

const TimelineChartCanvas = lazy(() => import('@/components/TimelineChartCanvas'))

export function TimelineChart({ alerts }: { alerts: Alert[] }) {
  const { t, i18n } = useTranslation()
  const buckets = useMemo(() => bucketAlertsPerHour(alerts), [alerts])
  if (buckets.length === 0) {
    return <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">{t('chart.empty')}</p>
  }
  const totalAlerts = buckets.reduce((runningTotal, bucket) => runningTotal + bucket.count, 0)
  const hourFormatter = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'short' })
  const summary = t('chart.summary', { count: totalAlerts, hours: buckets.length })
  return (
    <div>
      <div role="img" aria-label={summary}>
        <Suspense fallback={<Skeleton className="h-64 w-full" />}>
          <TimelineChartCanvas buckets={buckets} />
        </Suspense>
      </div>
      <table className="sr-only" aria-label={t('chart.label')}>
        <thead>
          <tr>
            <th scope="col">{t('chart.hour')}</th>
            <th scope="col">{t('chart.count')}</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((bucket) => (
            <tr key={bucket.hourStart}>
              <td>{hourFormatter.format(bucket.hourStart)}</td>
              <td>{formatNumber(bucket.count, i18n.language)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
