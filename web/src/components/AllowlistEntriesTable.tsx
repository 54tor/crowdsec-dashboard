import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { removeAllowlistEntry } from '@/api/allowlistsApi'
import type { AllowlistEntry, AllowlistMutation } from '@/api/types'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { PaginationBar } from '@/components/PaginationBar'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { UntrustedText } from '@/components/UntrustedText'
import { Badge } from '@/components/ui/badge'
import { formatDateTime } from '@/lib/format'

const ENTRIES_PER_PAGE = 50

interface AllowlistEntriesTableProps {
  engineName: string
  allowlistName: string
  entries: AllowlistEntry[]
  isWritable: boolean
  onWritten: (mutation: AllowlistMutation) => void
  disabledReason?: string
}

function EntryExpiry({ entry }: { entry: AllowlistEntry }) {
  const { t, i18n } = useTranslation()
  if (entry.expires_at === null) {
    return <>{t('allowlists.noExpiry')}</>
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      <time dateTime={entry.expires_at}>{formatDateTime(entry.expires_at, i18n.language)}</time>
      {entry.expired && <Badge variant="outline">{t('allowlists.expired')}</Badge>}
    </div>
  )
}

function EntryRemoveAction({ engineName, allowlistName, entry, onWritten, disabledReason }: Omit<AllowlistEntriesTableProps, 'entries' | 'isWritable'> & { entry: AllowlistEntry }) {
  const { t } = useTranslation()

  async function removeEntry(confirm: string) {
    const mutation = await removeAllowlistEntry(engineName, allowlistName, entry.value, confirm)
    onWritten(mutation)
    return mutation
  }

  return (
    <RowDeleteAction
      buttonLabel={t('allowlists.removeEntry')}
      ariaLabel={t('allowlists.removeEntryLabel', { value: entry.value })}
      title={t('allowlists.removeEntryTitle')}
      description={t('allowlists.removeEntryDescription', { name: allowlistName })}
      target={entry.value}
      request={removeEntry}
      invalidates={[]}
      disabledReason={disabledReason}
    />
  )
}

function useEntryColumns(props: Omit<AllowlistEntriesTableProps, 'entries'>): DataTableColumn<AllowlistEntry>[] {
  const { t, i18n } = useTranslation()
  const { engineName, allowlistName, isWritable, onWritten, disabledReason } = props
  return useMemo(() => {
    const columns: DataTableColumn<AllowlistEntry>[] = [
      { key: 'value', header: t('allowlists.columns.value'), cell: (entry) => <UntrustedText value={entry.value} /> },
      { key: 'description', header: t('allowlists.columns.description'), cell: (entry) => <UntrustedText value={entry.description} /> },
      { key: 'created', header: t('allowlists.columns.created'), cell: (entry) => formatDateTime(entry.created_at, i18n.language) },
      { key: 'expires', header: t('allowlists.columns.expires'), cell: (entry) => <EntryExpiry entry={entry} /> },
    ]
    if (isWritable) {
      columns.push({
        key: 'actions',
        header: t('allowlists.columns.actions'),
        cell: (entry) => <EntryRemoveAction engineName={engineName} allowlistName={allowlistName} entry={entry} onWritten={onWritten} disabledReason={disabledReason} />,
      })
    }
    return columns
  }, [t, i18n.language, engineName, allowlistName, isWritable, onWritten, disabledReason])
}

export function AllowlistEntriesTable({ entries, ...columnProps }: AllowlistEntriesTableProps) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const columns = useEntryColumns(columnProps)
  const totalPages = Math.max(1, Math.ceil(entries.length / ENTRIES_PER_PAGE))
  const currentPage = Math.min(page, totalPages)
  const visibleEntries = entries.slice((currentPage - 1) * ENTRIES_PER_PAGE, currentPage * ENTRIES_PER_PAGE)

  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('allowlists.noEntries')}</p>
  }
  return (
    <div className="space-y-2">
      <DataTable
        caption={t('allowlists.caption', { name: columnProps.allowlistName })}
        columns={columns}
        rows={visibleEntries}
        rowKey={(entry) => entry.value}
      />
      {totalPages > 1 && <PaginationBar page={currentPage} totalPages={totalPages} onPageChange={setPage} />}
    </div>
  )
}
