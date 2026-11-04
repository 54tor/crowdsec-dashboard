import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ENGINE_NAMES_QUERY_KEY, listEngineNames } from '@/api/enginesApi'
import { SelectField } from '@/components/SelectField'

interface EngineFilterProps {
  value: string
  onChange: (engineName: string) => void
}

export function EngineFilter({ value, onChange }: EngineFilterProps) {
  const { t } = useTranslation()
  const engineNamesQuery = useQuery({ queryKey: ENGINE_NAMES_QUERY_KEY, queryFn: listEngineNames, retry: false })
  const engineOptions = (engineNamesQuery.data ?? []).map((engineName) => ({ value: engineName.name, label: engineName.name }))
  return (
    <SelectField
      id="filter-engine"
      label={t('filters.engine')}
      value={value}
      options={[{ value: '', label: t('filters.allEngines') }, ...engineOptions]}
      onChange={onChange}
    />
  )
}
