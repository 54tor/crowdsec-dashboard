import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { AcquisitionMetric, MetricsAvailable, ParserMetric } from '@/api/types'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { formatNumber } from '@/lib/format'

export function MetricsTables({ metrics }: { metrics: MetricsAvailable }) {
  const { t, i18n } = useTranslation()
  const acquisitionColumns = useMemo<DataTableColumn<AcquisitionMetric>[]>(
    () => [
      { key: 'source', header: t('metrics.columns.source'), cell: (metricRow) => metricRow.source },
      { key: 'linesRead', header: t('metrics.columns.linesRead'), cell: (metricRow) => formatNumber(metricRow.lines_read, i18n.language) },
      { key: 'parsed', header: t('metrics.columns.parsed'), cell: (metricRow) => formatNumber(metricRow.parsed, i18n.language) },
      { key: 'unparsed', header: t('metrics.columns.unparsed'), cell: (metricRow) => formatNumber(metricRow.unparsed, i18n.language) },
    ],
    [t, i18n.language],
  )
  const parserColumns = useMemo<DataTableColumn<ParserMetric>[]>(
    () => [
      { key: 'parser', header: t('metrics.columns.parser'), cell: (metricRow) => metricRow.name },
      { key: 'hits', header: t('metrics.columns.hits'), cell: (metricRow) => formatNumber(metricRow.hits, i18n.language) },
      { key: 'parsed', header: t('metrics.columns.parsed'), cell: (metricRow) => formatNumber(metricRow.parsed, i18n.language) },
      { key: 'unparsed', header: t('metrics.columns.unparsed'), cell: (metricRow) => formatNumber(metricRow.unparsed, i18n.language) },
    ],
    [t, i18n.language],
  )
  if (metrics.acquisition.length === 0 && metrics.parsers.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('metrics.empty')}</p>
  }
  return (
    <div className="space-y-6">
      {metrics.acquisition.length > 0 && (
        <DataTable caption={t('metrics.acquisitionCaption')} columns={acquisitionColumns} rows={metrics.acquisition} rowKey={(metricRow) => metricRow.source} />
      )}
      {metrics.parsers.length > 0 && (
        <DataTable caption={t('metrics.parsersCaption')} columns={parserColumns} rows={metrics.parsers} rowKey={(metricRow) => metricRow.name} />
      )}
    </div>
  )
}
