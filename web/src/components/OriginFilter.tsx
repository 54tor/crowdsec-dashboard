import { useTranslation } from 'react-i18next'
import { SelectField } from '@/components/SelectField'

interface OriginFilterProps {
  value: string
  onChange: (sourceKind: string) => void
}

export function OriginFilter({ value, onChange }: OriginFilterProps) {
  const { t } = useTranslation()
  return (
    <SelectField
      id="filter-origin"
      label={t('filters.origin')}
      value={value}
      options={[
        { value: '', label: t('filters.allOrigins') },
        { value: 'log', label: t('filters.originLogs') },
        { value: 'appsec', label: t('filters.originAppSec') },
      ]}
      onChange={onChange}
    />
  )
}
