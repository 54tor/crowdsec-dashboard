import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from 'cn'
import { DataTableCards } from '@/components/DataTableCards'
import { EmptyState } from '@/components/EmptyState'
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useIsMobileViewport } from '@/hooks/useMediaQuery'
import { useTableDensity, type TableDensity } from '@/hooks/useTableDensity'

export type MobileColumnPlacement = 'primary' | 'secondary' | 'hidden' | 'actions'

export interface DataTableColumn<Row> {
  key: string
  header: string
  cell: (row: Row) => ReactNode
  className?: string
  mobile?: MobileColumnPlacement
  visibleFrom?: 'wide'
  noWrap?: boolean
}

interface DataTableProps<Row> {
  caption: string
  columns: DataTableColumn<Row>[]
  rows: Row[]
  rowKey: (row: Row) => string | number
  cardsOnMobile?: boolean
  emptyMessage?: string
}

const ROW_HEIGHT_BY_DENSITY: Record<TableDensity, string> = {
  comfortable: 'h-10',
  compact: 'h-8',
}

const CELL_PADDING_BY_DENSITY: Record<TableDensity, string> = {
  comfortable: 'py-1.5',
  compact: 'py-0.5',
}

const NO_WRAP_CELL_CLASSES = 'whitespace-nowrap [&_bdi]:whitespace-nowrap'

function tableCellClass<Row>(column: DataTableColumn<Row>, density: TableDensity): string {
  return cn(
    'whitespace-normal break-words',
    CELL_PADDING_BY_DENSITY[density],
    column.noWrap && NO_WRAP_CELL_CLASSES,
    column.className,
    columnVisibilityClass(column),
  )
}

function columnVisibilityClass<Row>(column: DataTableColumn<Row>): string | undefined {
  return column.visibleFrom === 'wide' ? 'hidden min-[1680px]:table-cell' : undefined
}

export function DataTable<Row>({ caption, columns, rows, rowKey, cardsOnMobile = false, emptyMessage }: DataTableProps<Row>) {
  const { t } = useTranslation()
  const { density } = useTableDensity()
  const isMobileViewport = useIsMobileViewport()
  if (rows.length === 0) {
    return <EmptyState message={emptyMessage ?? t('list.empty')} />
  }
  if (cardsOnMobile && isMobileViewport) {
    return <DataTableCards caption={caption} columns={columns} rows={rows} rowKey={rowKey} />
  }
  return (
    <div
      role="region"
      aria-label={t('list.scrollRegion', { name: caption })}
      tabIndex={0}
      className="max-h-[calc(100vh-14rem)] overflow-auto rounded-md border bg-card focus-ring"
    >
      <Table>
        <TableCaption className="sr-only">{caption}</TableCaption>
        <TableHeader>
          <TableRow>
            {columns.map((column) => (
              <TableHead key={column.key} scope="col" className={columnVisibilityClass(column)}>
                {column.header}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={rowKey(row)} className={ROW_HEIGHT_BY_DENSITY[density]}>
              {columns.map((column) => (
                <TableCell key={column.key} className={tableCellClass(column, density)}>
                  {column.cell(row)}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
