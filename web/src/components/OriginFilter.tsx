import { useTranslation } from 'react-i18next'
import { SegmentedControl } from '@/components/SegmentedControl'

interface OriginFilterProps {
  value: string
  onChange: (sourceKind: string) => void
}

export function OriginFilter({ value, onChange }: OriginFilterProps) {
  const { t } = useTranslation()
  return (
    <SegmentedControl
      name="filter-origin"
      legend={t('filters.origin')}
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
