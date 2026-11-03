import { useMemo, useState } from 'react'
import type { ListFilters } from '@/api/types'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { validateFilters } from '@/lib/filterValidation'

const FILTER_DEBOUNCE_MILLISECONDS = 300
const LOCAL_ENGINE_NAME = 'local'
const EMPTY_FILTERS: ListFilters = { scenario: '', ip: '', since: '', engine: '', source_kind: '' }

export function useListControls() {
  const [draftFilters, setDraftFilters] = useState<ListFilters>(EMPTY_FILTERS)
  const [page, setPage] = useState(1)
  const filters = useDebouncedValue(draftFilters, FILTER_DEBOUNCE_MILLISECONDS)
  const errors = useMemo(() => validateFilters(filters), [filters])

  function changeFilter(filterName: keyof ListFilters, value: string) {
    setDraftFilters((previousFilters) => ({ ...previousFilters, [filterName]: value.trim() }))
    setPage(1)
  }

  const isLiveWindowRead = filters.engine === '' || filters.engine === LOCAL_ENGINE_NAME

  return {
    draftFilters,
    isLiveWindowRead,
    filters,
    errors,
    isValid: Object.keys(errors).length === 0,
    page,
    setPage,
    changeFilter,
  }
}
