import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ENGINE_NAMES_QUERY_KEY, listEngineNames } from '@/api/enginesApi'
import { Label } from '@/components/ui/label'

interface EngineFilterProps {
  value: string
  onChange: (engineName: string) => void
}

export function EngineFilter({ value, onChange }: EngineFilterProps) {
  const { t } = useTranslation()
  const engineNamesQuery = useQuery({ queryKey: ENGINE_NAMES_QUERY_KEY, queryFn: listEngineNames, retry: false })
  return (
    <div className="space-y-1">
      <Label htmlFor="filter-engine">{t('filters.engine')}</Label>
      <select
        id="filter-engine"
        value={value}
        onChange={(changeEvent) => onChange(changeEvent.target.value)}
        className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-base outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 md:text-sm dark:bg-input/30"
      >
        <option value="">{t('filters.allEngines')}</option>
        {(engineNamesQuery.data ?? []).map((engineName) => (
          <option key={engineName.name} value={engineName.name}>
            {engineName.name}
          </option>
        ))}
      </select>
    </div>
  )
}
