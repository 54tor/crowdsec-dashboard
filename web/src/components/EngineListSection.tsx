import type { UseQueryResult } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { DensityToggle } from '@/components/DensityToggle'
import { EngineTargetSelect } from '@/components/EngineTargetSelect'
import { ErrorNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'

interface EngineListSectionProps<Row> {
  title: string
  selectId: string
  engineName: string
  onEngineChange: (engineName: string) => void
  toolbar: ReactNode
  query: UseQueryResult<Row[]>
  children: (rows: Row[], now: number) => ReactNode
}

export function EngineListSection<Row>({ title, selectId, engineName, onEngineChange, toolbar, query, children }: EngineListSectionProps<Row>) {
  const rows = query.data
  const showsDensityToggle = rows !== undefined && rows.length > 0
  return (
    <section className="space-y-4">
      <PageHeader
        title={title}
        actions={
          <>
            {showsDensityToggle && <DensityToggle />}
            {toolbar}
          </>
        }
      />
      <EngineTargetSelect id={selectId} value={engineName} onChange={onEngineChange} />
      {query.error && <ErrorNotice error={query.error} />}
      {query.isPending && <TableSkeleton />}
      {rows && children(rows, query.dataUpdatedAt)}
    </section>
  )
}
