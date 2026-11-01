import { useTranslation } from 'react-i18next'
import type { ListFilters } from '@/api/types'
import type { FilterErrors } from '@/lib/filterValidation'
import { EngineFilter } from '@/components/EngineFilter'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

interface FilterBarProps {
  values: ListFilters
  errors: FilterErrors
  onChange: (filterName: keyof ListFilters, value: string) => void
}

const FILTER_FIELDS = ['scenario', 'ip', 'since'] as const

export function FilterBar({ values, errors, onChange }: FilterBarProps) {
  const { t } = useTranslation()
  return (
    <form role="search" aria-label={t('filters.label')} onSubmit={(submitEvent) => submitEvent.preventDefault()} className="grid gap-3 sm:grid-cols-4">
      {FILTER_FIELDS.map((fieldName) => {
        const errorKey = errors[fieldName]
        const inputId = `filter-${fieldName}`
        return (
          <div key={fieldName} className="space-y-1">
            <Label htmlFor={inputId}>{t(`filters.${fieldName}`)}</Label>
            <Input
              id={inputId}
              value={values[fieldName]}
              onChange={(changeEvent) => onChange(fieldName, changeEvent.target.value)}
              placeholder={fieldName === 'since' ? t('filters.sincePlaceholder') : undefined}
              aria-invalid={errorKey ? true : undefined}
              aria-describedby={errorKey ? `${inputId}-error` : undefined}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
            />
            {errorKey && (
              <p id={`${inputId}-error`} className="text-sm text-destructive">
                {t(`filters.${errorKey}`)}
              </p>
            )}
          </div>
        )
      })}
      <EngineFilter value={values.engine} onChange={(engineName) => onChange('engine', engineName)} />
    </form>
  )
}
