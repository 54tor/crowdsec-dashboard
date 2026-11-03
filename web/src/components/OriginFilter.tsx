import { useTranslation } from 'react-i18next'
import { Label } from '@/components/ui/label'

interface OriginFilterProps {
  value: string
  onChange: (sourceKind: string) => void
}

export function OriginFilter({ value, onChange }: OriginFilterProps) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1">
      <Label htmlFor="filter-origin">{t('filters.origin')}</Label>
      <select
        id="filter-origin"
        value={value}
        onChange={(changeEvent) => onChange(changeEvent.target.value)}
        className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-base outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 md:text-sm dark:bg-input/30"
      >
        <option value="">{t('filters.allOrigins')}</option>
        <option value="log">{t('filters.originLogs')}</option>
        <option value="appsec">{t('filters.originAppSec')}</option>
      </select>
    </div>
  )
}
