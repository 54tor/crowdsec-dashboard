import { useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'

interface ClientFilterFieldProps {
  id: string
  label: string
  value: string
  onChange: (filterText: string) => void
  visibleCount: number
  totalCount: number
}

const FILTER_TEXT_MAXIMUM_LENGTH = 128
const COUNT_ANNOUNCEMENT_DELAY_MILLISECONDS = 300

export function ClientFilterField({ id, label, value, onChange, visibleCount, totalCount }: ClientFilterFieldProps) {
  const { t } = useTranslation()
  const filterInputReference = useRef<HTMLInputElement>(null)
  const countMessage = t('clientFilter.count', { visible: visibleCount, total: totalCount })
  const announcedCountMessage = useDebouncedValue(countMessage, COUNT_ANNOUNCEMENT_DELAY_MILLISECONDS)
  const countId = `${id}-count`

  function clearFilter() {
    onChange('')
    filterInputReference.current?.focus()
  }

  if (totalCount === 0) {
    return null
  }

  return (
    <div className="space-y-1 sm:max-w-md">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <Input
          ref={filterInputReference}
          id={id}
          type="search"
          autoComplete="off"
          spellCheck={false}
          maxLength={FILTER_TEXT_MAXIMUM_LENGTH}
          value={value}
          onChange={(changeEvent) => onChange(changeEvent.target.value)}
          aria-describedby={countId}
          className="pr-10 [&::-webkit-search-cancel-button]:appearance-none"
        />
        {value !== '' && (
          <Button type="button" variant="ghost" size="icon" className="absolute inset-y-0 right-0 h-full" aria-label={t('clientFilter.clear')} title={t('clientFilter.clear')} onClick={clearFilter}>
            <Icon name="close" />
          </Button>
        )}
      </div>
      <p id={countId} role="status" aria-live="polite" className="text-xs text-muted-foreground">
        {announcedCountMessage}
      </p>
    </div>
  )
}
