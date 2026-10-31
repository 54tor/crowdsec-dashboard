import { useTranslation } from 'react-i18next'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

interface HubFiltersProps {
  types: string[]
  selectedType: string
  nameQuery: string
  onTypeChange: (type: string) => void
  onNameChange: (nameQuery: string) => void
}

export function HubFilters({ types, selectedType, nameQuery, onTypeChange, onNameChange }: HubFiltersProps) {
  const { t } = useTranslation()
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-1">
        <Label htmlFor="hub-filter-type">{t('hub.filterType')}</Label>
        <select
          id="hub-filter-type"
          value={selectedType}
          onChange={(changeEvent) => onTypeChange(changeEvent.target.value)}
          className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-base outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 md:text-sm dark:bg-input/30"
        >
          <option value="">{t('hub.allTypes')}</option>
          {types.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </div>
      <div className="space-y-1">
        <Label htmlFor="hub-filter-name">{t('hub.filterName')}</Label>
        <Input id="hub-filter-name" value={nameQuery} onChange={(changeEvent) => onNameChange(changeEvent.target.value)} maxLength={128} autoComplete="off" spellCheck={false} />
      </div>
    </div>
  )
}
