import type { UseQueryResult } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import type { Page } from '@/api/types'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { PaginationBar } from '@/components/PaginationBar'
import { TableSkeleton } from '@/components/TableSkeleton'

interface PagedTableSectionProps<Row> {
  query: UseQueryResult<Page<Row>>
  page: number
  onPageChange: (page: number) => void
  caption: string
  columns: DataTableColumn<Row>[]
  rowKey: (row: Row) => string | number
}

export function PagedTableSection<Row>({ query, page, onPageChange, caption, columns, rowKey }: PagedTableSectionProps<Row>) {
  const { t } = useTranslation()
  const { data, error, isPending } = query
  if (error && !data) {
    return <ErrorNotice error={error} />
  }
  if (isPending || !data) {
    return <TableSkeleton />
  }
  const totalPages = Math.max(1, Math.ceil(data.window_size / data.per_page))
  return (
    <div className="space-y-3">
      {error && <ErrorNotice error={error} />}
      {data.may_be_truncated && <WarningNotice>{t('list.truncated', { count: data.window_size })}</WarningNotice>}
      {data.items.length === 0 ? (
        <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">{t('list.empty')}</p>
      ) : (
        <DataTable caption={caption} columns={columns} rows={data.items} rowKey={rowKey} />
      )}
      <p className="text-sm text-muted-foreground">{t('list.windowInfo', { count: data.window_size })}</p>
      <PaginationBar page={page} totalPages={totalPages} onPageChange={onPageChange} />
    </div>
  )
}
