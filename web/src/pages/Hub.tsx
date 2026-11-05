import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { HubItem } from '@/api/types'
import { ClientFilterResults } from '@/components/ClientFilterResults'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { ErrorNotice } from '@/components/Notice'
import { HubFilters } from '@/components/HubFilters'
import { HubTable } from '@/components/HubTable'
import { HubToolbar } from '@/components/HubToolbar'
import { WriteOnly } from '@/components/WriteOnly'
import { ReloadBanner } from '@/components/ReloadBanner'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useClientFilter } from '@/hooks/useClientFilter'
import { EngineTargetSelect } from '@/components/EngineTargetSelect'
import { useEngineTarget } from '@/hooks/useEngineTarget'
import { useHub } from '@/hooks/useReadResources'

const NO_HUB_ITEMS: HubItem[] = []

function hubItemSearchTexts(hubItem: HubItem): string[] {
  return [hubItem.type, hubItem.name, hubItem.status, hubItem.local_version, hubItem.description]
}

export function Hub() {
  const { t } = useTranslation()
  const [engineName, setEngineName] = useEngineTarget()
  const { data, error, isPending } = useHub(engineName)
  const [selectedType, setSelectedType] = useState('')
  const hubItems = data ?? NO_HUB_ITEMS

  const types = useMemo(() => [...new Set(hubItems.map((hubItem) => hubItem.type))].sort(), [hubItems])
  const itemsOfSelectedType = useMemo(
    () => hubItems.filter((hubItem) => selectedType === '' || hubItem.type === selectedType),
    [hubItems, selectedType],
  )
  const hubFilter = useClientFilter(itemsOfSelectedType, hubItemSearchTexts)
  const visibleItems = hubFilter.visibleRows

  return (
    <section className="space-y-4">
      <PageHeader title={t('hub.title')} />
      <EngineTargetSelect id="hub-engine" value={engineName} onChange={setEngineName} />
      <WriteOnly>
        <ReloadBanner engineName={engineName} />
        <HubToolbar engineName={engineName} />
      </WriteOnly>
      <HubFilters
        types={types}
        selectedType={selectedType}
        filterText={hubFilter.filterText}
        visibleCount={visibleItems.length}
        totalCount={hubItems.length}
        onTypeChange={setSelectedType}
        onFilterTextChange={hubFilter.setFilterText}
      />
      {error && <ErrorNotice error={error} />}
      {isPending && !error && <TableSkeleton />}
      {data && data.length === 0 && <EmptyState message={t('hub.noItems')} />}
      {data && data.length > 0 && (
        <ClientFilterResults visibleCount={visibleItems.length} totalCount={data.length}>
          <HubTable items={visibleItems} engineName={engineName} />
        </ClientFilterResults>
      )}
    </section>
  )
}
