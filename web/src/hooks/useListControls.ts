import { useMemo, useState } from 'react'
import type { ListFilters } from '@/api/types'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { validateFilters } from '@/lib/filterValidation'

const FILTER_DEBOUNCE_MILLISECONDS = 300
const EMPTY_FILTERS: ListFilters = { scenario: '', ip: '', since: '', engine: '' }

export function useListControls() {
  const [draftFilters, setDraftFilters] = useState<ListFilters>(EMPTY_FILTERS)
  const [page, setPage] = useState(1)
  const filters = useDebouncedValue(draftFilters, FILTER_DEBOUNCE_MILLISECONDS)
  const errors = useMemo(() => validateFilters(filters), [filters])

  function changeFilter(filterName: keyof ListFilters, value: string) {
    setDraftFilters((previousFilters) => ({ ...previousFilters, [filterName]: value.trim() }))
    setPage(1)
  }

  return {
    draftFilters,
    filters,
    errors,
    isValid: Object.keys(errors).length === 0,
    page,
    setPage,
    changeFilter,
  }
}
