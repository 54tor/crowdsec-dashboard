import type { UseQueryResult } from '@tanstack/react-query'
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import type { Page } from '@/api/types'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { ListSummary } from '@/components/ListSummary'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { PaginationBar } from '@/components/PaginationBar'
import { TableSkeleton } from '@/components/TableSkeleton'
import { isInvalidRequestError } from '@/lib/apiErrors'

interface PagedTableSectionProps<Row> {
  query: UseQueryResult<Page<Row>>
  page: number
  onPageChange: (page: number) => void
  caption: string
  columns: DataTableColumn<Row>[]
  rowKey: (row: Row) => string | number
  isLiveWindowRead?: boolean
  cardsOnMobile?: boolean
}

function totalPagesOf<Row>(data: Page<Row>): number {
  const reachableRows = data.total ?? data.window_size
  return Math.max(1, Math.ceil(reachableRows / data.per_page))
}

function ListErrorNotice({ error }: { error: unknown }) {
  const { t } = useTranslation()
  return <ErrorNotice error={error} message={isInvalidRequestError(error) ? t('list.invalidRequest') : undefined} />
}

function useKeepPageInRange(page: number, lastExistingPage: number | undefined, onPageChange: (page: number) => void) {
  useEffect(() => {
    const isPageBeyondTheEnd = lastExistingPage !== undefined && page > lastExistingPage
    if (isPageBeyondTheEnd) {
      onPageChange(lastExistingPage)
    }
  }, [page, lastExistingPage, onPageChange])
}

export function PagedTableSection<Row>({ query, page, onPageChange, caption, columns, rowKey, isLiveWindowRead = true, cardsOnMobile = false }: PagedTableSectionProps<Row>) {
  const { t } = useTranslation()
  const { data, error, isPending } = query
  useKeepPageInRange(page, data ? totalPagesOf(data) : undefined, onPageChange)
  if (error && !data) {
    return <ListErrorNotice error={error} />
  }
  if (isPending || !data) {
    return <TableSkeleton />
  }
  return (
    <div className="space-y-3">
      {error && <ListErrorNotice error={error} />}
      {data.live_status === 'unavailable' && <WarningNotice>{t('list.liveUnavailable')}</WarningNotice>}
      {data.may_be_truncated && <WarningNotice>{t('list.truncated', { count: data.window_size })}</WarningNotice>}
      <DataTable caption={caption} columns={columns} rows={data.items} rowKey={rowKey} cardsOnMobile={cardsOnMobile} />
      <ListSummary data={data} />
      {isLiveWindowRead && data.live_status !== 'unavailable' && <p className="text-sm text-muted-foreground">{t('list.windowInfo', { count: data.window_size })}</p>}
      <PaginationBar page={page} totalPages={totalPagesOf(data)} onPageChange={onPageChange} />
    </div>
  )
}
