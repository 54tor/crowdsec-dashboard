import { useTranslation } from 'react-i18next'
import { SelectField } from '@/components/SelectField'
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
      <div className="space-y-1">
        <Label htmlFor="hub-filter-name">{t('hub.filterName')}</Label>
        <Input id="hub-filter-name" value={nameQuery} onChange={(changeEvent) => onNameChange(changeEvent.target.value)} maxLength={128} autoComplete="off" spellCheck={false} />
      </div>
    </div>
  )
}
