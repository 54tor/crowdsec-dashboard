import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Decision } from '@/api/types'
import type { DataTableColumn } from '@/components/DataTable'
import { FilterBar } from '@/components/FilterBar'
import { InfoNotice } from '@/components/Notice'
import { PagedTableSection } from '@/components/PagedTableSection'
import { Badge } from '@/components/ui/badge'
import { PAGE_SIZE, usePagedList } from '@/hooks/usePagedList'
import { useListControls } from '@/hooks/useListControls'
import { formatDateTime } from '@/lib/format'

export function Decisions() {
  const { t, i18n } = useTranslation()
  const controls = useListControls()
  const query = usePagedList<Decision>('decisions', controls.filters, controls.page, PAGE_SIZE, controls.isValid)

  const columns = useMemo<DataTableColumn<Decision>[]>(
    () => [
      { key: 'value', header: t('decisions.columns.value'), cell: (decision) => decision.value },
      { key: 'scope', header: t('decisions.columns.scope'), cell: (decision) => decision.scope },
      { key: 'type', header: t('decisions.columns.type'), cell: (decision) => decision.type },
      { key: 'origin', header: t('decisions.columns.origin'), cell: (decision) => decision.origin },
      {
        key: 'scenario',
        header: t('decisions.columns.scenario'),
        cell: (decision) => (
          <>
            {decision.scenario}
            {decision.simulated && <Badge variant="outline" className="ml-2">{t('decisions.columns.simulated')}</Badge>}
          </>
        ),
      },
      {
        key: 'expires',
        header: t('decisions.columns.expires'),
        className: 'whitespace-nowrap',
        cell: (decision) => (decision.until ? formatDateTime(decision.until, i18n.language) : decision.duration),
      },
    ],
    [t, i18n.language],
  )

  return (
    <section className="space-y-4">
      <h1 className="text-xl font-semibold">{t('decisions.title')}</h1>
      <InfoNotice>{t('decisions.communityNotice')}</InfoNotice>
      <FilterBar values={controls.draftFilters} errors={controls.errors} onChange={controls.changeFilter} />
      <PagedTableSection
        query={query}
        page={controls.page}
        onPageChange={controls.setPage}
        caption={t('decisions.caption')}
        columns={columns}
        rowKey={(decision) => decision.id}
      />
    </section>
  )
}
