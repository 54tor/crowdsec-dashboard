import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { SyncPlanEntry } from '@/api/syncApi'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { UntrustedText } from '@/components/UntrustedText'
import { translateSyncCode } from '@/lib/syncCodes'

export function SyncPlanTable({ entries }: { entries: SyncPlanEntry[] }) {
  const { t } = useTranslation()
  const columns = useMemo<DataTableColumn<SyncPlanEntry>[]>(
    () => [
      { key: 'engine', header: t('sync.columns.name'), cell: (entry) => <UntrustedText value={entry.engine} /> },
      { key: 'kind', header: t('sync.columns.kind'), cell: (entry) => (entry.kind === '' ? '—' : translateSyncCode(t, 'kinds', entry.kind)) },
      { key: 'target', header: t('sync.columns.target'), cell: (entry) => <UntrustedText value={entry.target} /> },
      { key: 'source', header: t('sync.columns.source'), cell: (entry) => (entry.source === '' ? '—' : <UntrustedText value={entry.source} />) },
      { key: 'reason', header: t('sync.columns.reason'), cell: (entry) => (entry.reason === '' ? '—' : translateSyncCode(t, 'reasons', entry.reason)) },
    ],
    [t],
  )
  return (
    <DataTable
      caption={t('sync.planTableCaption')}
      columns={columns}
      rows={entries}
      rowKey={(entry) => `${entry.engine}|${entry.kind}|${entry.target}|${entry.source}|${entry.reason}`}
    />
  )
}
