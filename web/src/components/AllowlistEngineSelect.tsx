import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ENGINE_NAMES_QUERY_KEY, listEngineNames } from '@/api/enginesApi'
import { ErrorNotice } from '@/components/Notice'
import { SelectField } from '@/components/SelectField'

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
      <SelectField
        id="allowlists-engine"
        label={t('allowlists.engine')}
        value={value}
        options={selectableNames.map((engineName) => ({ value: engineName, label: engineName }))}
        onChange={onChange}
      />
      {engineNamesQuery.error && <ErrorNotice error={engineNamesQuery.error} />}
    </div>
  )
}
