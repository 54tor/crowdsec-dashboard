import { useTranslation } from 'react-i18next'
import { ClientFilterField } from '@/components/ClientFilterField'
import { SelectField } from '@/components/SelectField'

interface HubFiltersProps {
  types: string[]
  selectedType: string
  filterText: string
  visibleCount: number
  totalCount: number
  onTypeChange: (type: string) => void
  onFilterTextChange: (filterText: string) => void
}

export function HubFilters({ types, selectedType, filterText, visibleCount, totalCount, onTypeChange, onFilterTextChange }: HubFiltersProps) {
  const { t } = useTranslation()
  const typeOptions = types.map((type) => ({ value: type, label: type }))
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <SelectField
        id="hub-filter-type"
        label={t('hub.filterType')}
        value={selectedType}
        options={[{ value: '', label: t('hub.allTypes') }, ...typeOptions]}
        onChange={onTypeChange}
      />
      <ClientFilterField
        id="hub-filter-text"
        label={t('clientFilter.label')}
        value={filterText}
        onChange={onFilterTextChange}
        visibleCount={visibleCount}
        totalCount={totalCount}
      />
    </div>
  )
}
