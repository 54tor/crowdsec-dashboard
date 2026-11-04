import { useTranslation } from 'react-i18next'
import { MetricsTables } from '@/components/MetricsTables'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useMetrics } from '@/hooks/useReadResources'

export function Metrics() {
  const { t } = useTranslation()
  const { data, error, isPending } = useMetrics()
  return (
    <section className="space-y-4">
      <PageHeader title={t('metrics.title')} />
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {data && !data.available && (
        <WarningNotice title={t('metrics.unavailableTitle')}>{t('metrics.unavailable')}</WarningNotice>
      )}
      {data?.available && <MetricsTables metrics={data} />}
    </section>
  )
}
