import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ENGINE_NAMES_QUERY_KEY, listEngineNames } from '@/api/enginesApi'
import { ErrorNotice } from '@/components/Notice'
import { Label } from '@/components/ui/label'

interface AllowlistEngineSelectProps {
  value: string
  onChange: (engineName: string) => void
}

export function AllowlistEngineSelect({ value, onChange }: AllowlistEngineSelectProps) {
  const { t } = useTranslation()
  const engineNamesQuery = useQuery({ queryKey: ENGINE_NAMES_QUERY_KEY, queryFn: listEngineNames, retry: false })
  const engineNames = (engineNamesQuery.data ?? []).map((engine) => engine.name)
  const selectableNames = engineNames.includes(value) ? engineNames : [value, ...engineNames]
  return (
    <div className="max-w-xs space-y-1">
      <Label htmlFor="allowlists-engine">{t('allowlists.engine')}</Label>
      <select
        id="allowlists-engine"
        value={value}
        onChange={(changeEvent) => onChange(changeEvent.target.value)}
        className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-base outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 md:text-sm dark:bg-input/30"
      >
        {selectableNames.map((engineName) => (
          <option key={engineName} value={engineName}>
            {engineName}
          </option>
        ))}
      </select>
      {engineNamesQuery.error && <ErrorNotice error={engineNamesQuery.error} />}
    </div>
  )
}
