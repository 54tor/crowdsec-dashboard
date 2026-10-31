import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ErrorNotice } from '@/components/Notice'
import { HubFilters } from '@/components/HubFilters'
import { HubTable } from '@/components/HubTable'
import { HubToolbar } from '@/components/HubToolbar'
import { ReloadBanner } from '@/components/ReloadBanner'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useHub } from '@/hooks/useReadResources'

export function Hub() {
  const { t } = useTranslation()
  const { data, error, isPending } = useHub()
  const [selectedType, setSelectedType] = useState('')
  const [nameQuery, setNameQuery] = useState('')

  const types = useMemo(() => [...new Set((data ?? []).map((hubItem) => hubItem.type))].sort(), [data])
  const visibleItems = useMemo(() => {
    const lowerCaseQuery = nameQuery.toLowerCase()
    return (data ?? []).filter(
      (hubItem) => (selectedType === '' || hubItem.type === selectedType) && hubItem.name.toLowerCase().includes(lowerCaseQuery),
    )
  }, [data, selectedType, nameQuery])

  return (
    <section className="space-y-4">
      <h1 className="text-xl font-semibold">{t('hub.title')}</h1>
      <ReloadBanner />
      <HubToolbar />
      <HubFilters types={types} selectedType={selectedType} nameQuery={nameQuery} onTypeChange={setSelectedType} onNameChange={setNameQuery} />
      {error && <ErrorNotice error={error} />}
      {isPending && !error && <TableSkeleton />}
      {data && visibleItems.length === 0 && (
        <p className="rounded-lg border p-6 text-center text-sm text-muted-foreground">{t(data.length === 0 ? 'hub.noItems' : 'hub.empty')}</p>
      )}
      {data && visibleItems.length > 0 && <HubTable items={visibleItems} />}
    </section>
  )
}
