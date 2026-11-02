import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { EngineHealth } from '@/api/types'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Badge } from '@/components/ui/badge'
import { formatDateTime, formatDuration, formatNumber, formatRelativeAge } from '@/lib/format'

function LastSuccessCell({ engine, now }: { engine: EngineHealth; now: number }) {
  const { t, i18n } = useTranslation()
  if (engine.last_success_at === null) {
    return <>{t('health.collector.neverSinceStartup')}</>
  }
  return (
    <time dateTime={engine.last_success_at} title={formatDateTime(engine.last_success_at, i18n.language)}>
      {formatRelativeAge(engine.last_success_at, now, i18n.language)}
    </time>
  )
}

export function CollectorTable({ engines, now }: { engines: EngineHealth[]; now: number }) {
  const { t, i18n } = useTranslation()
  const columns = useMemo<DataTableColumn<EngineHealth>[]>(
    () => [
      { key: 'name', header: t('health.columns.name'), cell: (engine) => engine.engine_name },
      { key: 'lastSuccess', header: t('health.collector.lastSuccess'), cell: (engine) => <LastSuccessCell engine={engine} now={now} /> },
      {
        key: 'lag',
        header: t('health.collector.lag'),
        cell: (engine) => (engine.lag_seconds === null ? '—' : formatDuration(engine.lag_seconds, i18n.language)),
      },
      { key: 'errors', header: t('health.collector.errors'), cell: (engine) => formatNumber(engine.errors_total, i18n.language) },
      {
        key: 'status',
        header: t('health.columns.status'),
        cell: (engine) => <Badge variant="outline">{engine.stale ? t('health.collector.stale') : t('health.ok')}</Badge>,
      },
    ],
    [t, i18n.language, now],
  )
  if (engines.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('health.collector.empty')}</p>
  }
  return <DataTable caption={t('health.collector.tableCaption')} columns={columns} rows={engines} rowKey={(engine) => engine.engine_name} />
}
