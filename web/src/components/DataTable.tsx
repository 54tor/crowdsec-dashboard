import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

export interface DataTableColumn<Row> {
  key: string
  header: string
  cell: (row: Row) => ReactNode
  className?: string
}

interface DataTableProps<Row> {
  caption: string
  columns: DataTableColumn<Row>[]
  rows: Row[]
  rowKey: (row: Row) => string | number
}

export function DataTable<Row>({ caption, columns, rows, rowKey }: DataTableProps<Row>) {
  const { t } = useTranslation()
  return (
    <div
      role="region"
      aria-label={t('list.scrollRegion', { name: caption })}
      tabIndex={0}
      className="overflow-x-auto rounded-lg border outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <Table>
        <TableCaption className="sr-only">{caption}</TableCaption>
        <TableHeader>
          <TableRow>
            {columns.map((column) => (
              <TableHead key={column.key} scope="col" className={column.className}>
                {column.header}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={rowKey(row)}>
              {columns.map((column) => (
                <TableCell key={column.key} className={column.className ?? 'whitespace-normal break-words'}>
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
