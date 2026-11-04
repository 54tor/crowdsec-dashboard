import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Alert } from '@/api/types'
import { AlertRowActions } from '@/components/AlertRowActions'
import { AlertStatusBadge } from '@/components/AlertStatusBadge'
import type { DataTableColumn } from '@/components/DataTable'
import { DensityToggle } from '@/components/DensityToggle'
import { EngineCell } from '@/components/EngineCell'
import { FilterBar } from '@/components/FilterBar'
import { FiltersDisclosure } from '@/components/FiltersDisclosure'
import { PagedTableSection } from '@/components/PagedTableSection'
import { PageHeader } from '@/components/PageHeader'
import { TimelineChart } from '@/components/TimelineChart'
import { UntrustedText } from '@/components/UntrustedText'
import { Badge } from '@/components/ui/badge'
import { PAGE_SIZE, usePagedList } from '@/hooks/usePagedList'
import { useListControls } from '@/hooks/useListControls'
import { formatDateTimeToMinute, formatNumber } from '@/lib/format'

const CHART_WINDOW_SIZE = 100

function sourceLabel(alertRow: Alert): string {
  const details = [alertRow.source.cn, alertRow.source.as_name].filter(Boolean).join(' · ')
  return details ? `${alertRow.source.value} (${details})` : alertRow.source.value
}

function alertRowKey(alertRow: Alert): string {
  return `${alertRow.engine}/${alertRow.id}/${alertRow.uuid ?? ''}`
}

export function Alerts() {
  const { t, i18n } = useTranslation()
  const controls = useListControls()
  const tableQuery = usePagedList<Alert>('alerts', controls.filters, controls.page, PAGE_SIZE, controls.isValid)
  const chartQuery = usePagedList<Alert>('alerts', controls.filters, 1, CHART_WINDOW_SIZE, controls.isValid)

  const columns = useMemo<DataTableColumn<Alert>[]>(
    () => [
      { key: 'status', header: t('alerts.columns.status'), mobile: 'primary', cell: (alertRow) => <AlertStatusBadge alertRow={alertRow} /> },
      {
        key: 'createdAt',
        header: t('alerts.columns.createdAt'),
        mobile: 'primary',
        className: 'whitespace-nowrap font-mono',
        cell: (alertRow) => formatDateTimeToMinute(alertRow.created_at, i18n.language),
      },
      {
        key: 'engine',
        header: t('alerts.columns.engine'),
        cell: (alertRow) => (
          <EngineCell
            engineName={alertRow.engine}
            badgeLabel={alertRow.live ? t('alerts.liveBadge') : t('alerts.archivedBadge')}
            machineId={alertRow.machine_id}
          />
        ),
      },
      {
        key: 'scenario',
        header: t('alerts.columns.scenario'),
        className: 'font-mono',
        cell: (alertRow) => (
          <>
            <UntrustedText value={alertRow.scenario} />
            {alertRow.source_kind === 'appsec' && <Badge variant="info" className="ml-2">{t('alerts.appSecBadge')}</Badge>}
          </>
        ),
      },
      { key: 'source', header: t('alerts.columns.source'), className: 'font-mono', cell: (alertRow) => <UntrustedText value={sourceLabel(alertRow)} /> },
      { key: 'events', header: t('alerts.columns.events'), cell: (alertRow) => formatNumber(alertRow.events_count, i18n.language) },
      { key: 'decisions', header: t('alerts.columns.decisions'), cell: (alertRow) => formatNumber(alertRow.decisions.length, i18n.language) },
      {
        key: 'message',
        header: t('alerts.columns.message'),
        mobile: 'hidden',
        visibleFrom: 'wide',
        cell: (alertRow) => <UntrustedText value={alertRow.message} />,
      },
      { key: 'actions', header: t('alerts.actions'), mobile: 'actions', cell: (alertRow) => <AlertRowActions alertRow={alertRow} /> },
    ],
    [t, i18n.language],
  )

  return (
    <section className="space-y-4">
      <PageHeader title={t('alerts.title')} actions={<DensityToggle />} />
      <FiltersDisclosure>
        <FilterBar values={controls.draftFilters} errors={controls.errors} onChange={controls.changeFilter} showOriginFilter />
      </FiltersDisclosure>
      <section aria-labelledby="alerts-chart-title" className="space-y-2">
        <h2 id="alerts-chart-title" className="text-base font-medium">{t('alerts.chartTitle')}</h2>
        <TimelineChart alerts={chartQuery.data?.items ?? []} />
      </section>
      <PagedTableSection
        query={tableQuery}
        page={controls.page}
        onPageChange={controls.setPage}
        isLiveWindowRead={controls.isLiveWindowRead}
        caption={t('alerts.caption')}
        columns={columns}
        rowKey={alertRowKey}
        cardsOnMobile
        emptyMessage={t('alerts.empty')}
      />
    </section>
  )
}
