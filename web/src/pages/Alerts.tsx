import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Alert } from '@/api/types'
import type { DataTableColumn } from '@/components/DataTable'
import { FilterBar } from '@/components/FilterBar'
import { PagedTableSection } from '@/components/PagedTableSection'
import { TimelineChart } from '@/components/TimelineChart'
import { Badge } from '@/components/ui/badge'
import { PAGE_SIZE, usePagedList } from '@/hooks/usePagedList'
import { useListControls } from '@/hooks/useListControls'
import { formatDateTime, formatNumber } from '@/lib/format'

const CHART_WINDOW_SIZE = 100

function sourceLabel(alertRow: Alert): string {
  const details = [alertRow.source.cn, alertRow.source.as_name].filter(Boolean).join(' · ')
  return details ? `${alertRow.source.value} (${details})` : alertRow.source.value
}

export function Alerts() {
  const { t, i18n } = useTranslation()
  const controls = useListControls()
  const tableQuery = usePagedList<Alert>('alerts', controls.filters, controls.page, PAGE_SIZE, controls.isValid)
  const chartQuery = usePagedList<Alert>('alerts', controls.filters, 1, CHART_WINDOW_SIZE, controls.isValid)

  const columns = useMemo<DataTableColumn<Alert>[]>(
    () => [
      { key: 'createdAt', header: t('alerts.columns.createdAt'), className: 'whitespace-nowrap', cell: (alertRow) => formatDateTime(alertRow.created_at, i18n.language) },
      {
        key: 'scenario',
        header: t('alerts.columns.scenario'),
        cell: (alertRow) => (
          <>
            {alertRow.scenario}
            {alertRow.simulated && <Badge variant="outline" className="ml-2">{t('alerts.simulated')}</Badge>}
          </>
        ),
      },
      { key: 'source', header: t('alerts.columns.source'), cell: sourceLabel },
      { key: 'machine', header: t('alerts.columns.machine'), cell: (alertRow) => alertRow.machine_id },
      { key: 'events', header: t('alerts.columns.events'), cell: (alertRow) => formatNumber(alertRow.events_count, i18n.language) },
      { key: 'decisions', header: t('alerts.columns.decisions'), cell: (alertRow) => formatNumber(alertRow.decisions.length, i18n.language) },
      { key: 'message', header: t('alerts.columns.message'), cell: (alertRow) => alertRow.message },
    ],
    [t, i18n.language],
  )

  return (
    <section className="space-y-4">
      <h1 className="text-xl font-semibold">{t('alerts.title')}</h1>
      <FilterBar values={controls.draftFilters} errors={controls.errors} onChange={controls.changeFilter} />
      <section aria-labelledby="alerts-chart-title" className="space-y-2">
        <h2 id="alerts-chart-title" className="text-base font-medium">{t('alerts.chartTitle')}</h2>
        <TimelineChart alerts={chartQuery.data?.items ?? []} />
      </section>
      <PagedTableSection
        query={tableQuery}
        page={controls.page}
        onPageChange={controls.setPage}
        caption={t('alerts.caption')}
        columns={columns}
        rowKey={(alertRow) => alertRow.id}
      />
    </section>
  )
}
