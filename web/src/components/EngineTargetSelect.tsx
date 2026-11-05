import { useTranslation } from 'react-i18next'
import { SelectField } from '@/components/SelectField'
import { useWritableEngineNames } from '@/hooks/useEngineTarget'
import { useIsEngineWritePending } from '@/hooks/useIsEngineWritePending'

interface EngineTargetSelectProps {
  id: string
  value: string
  onChange: (engineName: string) => void
  disabled?: boolean
}

export function EngineTargetSelect({ id, value, onChange, disabled }: EngineTargetSelectProps) {
  const { t } = useTranslation()
  const writableEngineNames = useWritableEngineNames()
  const isEngineWritePending = useIsEngineWritePending()
  if (writableEngineNames === undefined) {
    return null
  }
  return (
    <div className="max-w-xs">
      <SelectField
        id={id}
        label={t('engineTarget.label')}
        hint={t('engineTarget.hint')}
        value={value}
        disabled={disabled || isEngineWritePending}
        options={writableEngineNames.map((engineName) => ({ value: engineName, label: engineName }))}
        onChange={onChange}
      />
    </div>
  )
}
