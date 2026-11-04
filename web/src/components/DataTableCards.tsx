import { cn } from 'cn'
import type { DataTableColumn, MobileColumnPlacement } from '@/components/DataTable'

interface DataTableCardsProps<Row> {
  caption: string
  columns: DataTableColumn<Row>[]
  rows: Row[]
  rowKey: (row: Row) => string | number
}

const CARD_CELL_WRAP_CLASSES = 'min-w-0 whitespace-normal break-words'

function columnsPlacedAt<Row>(columns: DataTableColumn<Row>[], placement: MobileColumnPlacement): DataTableColumn<Row>[] {
  return columns.filter((column) => (column.mobile ?? 'secondary') === placement)
}

function cardCellClass<Row>(column: DataTableColumn<Row>): string {
  return cn(column.className, CARD_CELL_WRAP_CLASSES)
}

export function DataTableCards<Row>({ caption, columns, rows, rowKey }: DataTableCardsProps<Row>) {
  const primaryColumns = columnsPlacedAt(columns, 'primary')
  const secondaryColumns = columnsPlacedAt(columns, 'secondary')
  const actionColumns = columnsPlacedAt(columns, 'actions')
  return (
    <ul role="list" aria-label={caption} className="space-y-3">
      {rows.map((row) => (
        <li key={rowKey(row)} className="min-w-0 space-y-2 rounded-md border bg-card p-3">
          {primaryColumns.length > 0 && (
            <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1 font-medium">
              {primaryColumns.map((column) => (
                <div key={column.key} className={cardCellClass(column)}>
                  <span className="sr-only">{column.header} </span>
                  {column.cell(row)}
                </div>
              ))}
            </div>
          )}
          {secondaryColumns.length > 0 && (
            <dl className="grid grid-cols-[minmax(0,auto)_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
              {secondaryColumns.map((column) => (
                <div key={column.key} className="contents">
                  <dt className="font-condensed text-xs tracking-wide text-muted-foreground uppercase">{column.header}</dt>
                  <dd className={cardCellClass(column)}>{column.cell(row)}</dd>
                </div>
              ))}
            </dl>
          )}
          {actionColumns.length > 0 && (
            <div className="flex min-w-0 flex-wrap justify-end gap-2 border-t pt-2">
              {actionColumns.map((column) => (
                <div key={column.key} className="min-w-0">
                  {column.cell(row)}
                </div>
              ))}
            </div>
          )}
        </li>
      ))}
    </ul>
  )
}
