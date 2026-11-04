import { useTranslation } from 'react-i18next'
import type { ListFilters } from '@/api/types'
import type { FilterErrors } from '@/lib/filterValidation'
import { EngineFilter } from '@/components/EngineFilter'
import { FormField } from '@/components/FormField'
import { OriginFilter } from '@/components/OriginFilter'

interface FilterBarProps {
  values: ListFilters
  errors: FilterErrors
  onChange: (filterName: keyof ListFilters, value: string) => void
  showOriginFilter?: boolean
}

const FILTER_FIELDS = ['scenario', 'ip', 'since'] as const

export function FilterBar({ values, errors, onChange, showOriginFilter = false }: FilterBarProps) {
  const { t } = useTranslation()
  return (
    <form role="search" aria-label={t('filters.label')} onSubmit={(submitEvent) => submitEvent.preventDefault()} className="grid gap-3 sm:grid-cols-4">
      {FILTER_FIELDS.map((fieldName) => {
        const errorKey = errors[fieldName]
        return (
          <FormField
            key={fieldName}
            id={`filter-${fieldName}`}
            label={t(`filters.${fieldName}`)}
            value={values[fieldName]}
            onChange={(changeEvent) => onChange(fieldName, changeEvent.target.value)}
            placeholder={fieldName === 'since' ? t('filters.sincePlaceholder') : undefined}
            error={errorKey ? t(`filters.${errorKey}`) : null}
            maxLength={128}
          />
        )
      })}
      <EngineFilter value={values.engine} onChange={(engineName) => onChange('engine', engineName)} />
      {showOriginFilter && <OriginFilter value={values.source_kind} onChange={(sourceKind) => onChange('source_kind', sourceKind)} />}
    </form>
  )
}
