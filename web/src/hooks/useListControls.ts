import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router'
import type { ListFilters } from '@/api/types'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useKnownEngineNames } from '@/hooks/useKnownEngineNames'
import { validateFilters } from '@/lib/filterValidation'

const FILTER_DEBOUNCE_MILLISECONDS = 300
const LOCAL_ENGINE_NAME = 'local'
const EMPTY_FILTERS: ListFilters = { q: '', scenario: '', ip: '', since: '', engine: '', source_kind: '' }

function filtersFromUrl(searchParams: URLSearchParams): ListFilters {
  return { ...EMPTY_FILTERS, q: searchParams.get('q') ?? '', engine: searchParams.get('engine') ?? '' }
}

function isEngineKnown(engineName: string, knownEngineNames: string[] | undefined): boolean {
  return engineName === '' || (knownEngineNames?.includes(engineName) ?? false)
}

export function useListControls() {
  const [searchParams] = useSearchParams()
  const currentUrlSearch = searchParams.toString()
  const knownEngineNames = useKnownEngineNames()
  const [draftFilters, setDraftFilters] = useState<ListFilters>(() => filtersFromUrl(searchParams))
  const [appliedUrlSearch, setAppliedUrlSearch] = useState(currentUrlSearch)
  const [page, setPage] = useState(1)

  if (appliedUrlSearch !== currentUrlSearch) {
    setAppliedUrlSearch(currentUrlSearch)
    setDraftFilters(filtersFromUrl(searchParams))
    setPage(1)
  }
  const isDraftEngineUnknown = knownEngineNames !== undefined && !isEngineKnown(draftFilters.engine, knownEngineNames)
  if (isDraftEngineUnknown) {
    setDraftFilters((previousFilters) => ({ ...previousFilters, engine: '' }))
  }

  const filters = useDebouncedValue(draftFilters, FILTER_DEBOUNCE_MILLISECONDS)
  const errors = useMemo(() => validateFilters(filters), [filters])

  function changeFilter(filterName: keyof ListFilters, value: string) {
    const keptValue = filterName === 'q' ? value : value.trim()
    setDraftFilters((previousFilters) => ({ ...previousFilters, [filterName]: keptValue }))
    setPage(1)
  }

  const isValid = Object.keys(errors).length === 0
  const isLiveWindowRead = filters.engine === '' || filters.engine === LOCAL_ENGINE_NAME
  const activeFilterCount = Object.values(draftFilters).filter((filterValue) => filterValue.trim() !== '').length

  return {
    activeFilterCount,
    draftFilters,
    isLiveWindowRead,
    filters,
    errors,
    isValid,
    isReadyToQuery: isValid && isEngineKnown(filters.engine, knownEngineNames),
    page,
    setPage,
    changeFilter,
  }
}
