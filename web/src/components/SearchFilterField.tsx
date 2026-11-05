import { useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { FieldMessages } from '@/components/FieldMessages'
import { Icon } from '@/components/Icon'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { describedByIds } from '@/lib/fieldDescription'
import { SEARCH_TERM_MAXIMUM_LENGTH } from '@/lib/filterValidation'

interface SearchFilterFieldProps {
  value: string
  error: string | null
  onChange: (searchTerm: string) => void
  hint?: string
}

const SEARCH_FIELD_ID = 'filter-q'

export function SearchFilterField({ value, error, onChange, hint }: SearchFilterFieldProps) {
  const { t } = useTranslation()
  const searchInputReference = useRef<HTMLInputElement>(null)
  const displayedHint = hint ?? t('filters.qHint')

  function clearSearch() {
    onChange('')
    searchInputReference.current?.focus()
  }

  return (
    <div className="space-y-1 sm:col-span-2">
      <Label htmlFor={SEARCH_FIELD_ID}>{t('filters.q')}</Label>
      <div className="relative">
        <Input
          ref={searchInputReference}
          id={SEARCH_FIELD_ID}
          type="search"
          autoComplete="off"
          spellCheck={false}
          maxLength={SEARCH_TERM_MAXIMUM_LENGTH}
          value={value}
          onChange={(changeEvent) => onChange(changeEvent.target.value)}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedByIds(SEARCH_FIELD_ID, displayedHint, error)}
          className="pr-10 [&::-webkit-search-cancel-button]:appearance-none"
        />
        {value !== '' && (
          <Button type="button" variant="ghost" size="icon" className="absolute inset-y-0 right-0 h-full" aria-label={t('filters.qClear')} title={t('filters.qClear')} onClick={clearSearch}>
            <Icon name="close" />
          </Button>
        )}
      </div>
      <FieldMessages fieldId={SEARCH_FIELD_ID} hint={displayedHint} error={error} />
    </div>
  )
}
