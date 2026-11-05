import { useCallback, useMemo, useState } from 'react'
import { useLocation, useSearchParams } from 'react-router'
import type { ListFilters } from '@/api/types'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useKnownEngineNames } from '@/hooks/useKnownEngineNames'
import { EMPTY_FILTERS } from '@/lib/emptyFilters'
import { validateFilters } from '@/lib/filterValidation'

export const FILTER_DEBOUNCE_MILLISECONDS = 300
const LOCAL_ENGINE_NAME = 'local'

function filtersFromUrl(searchParams: URLSearchParams): ListFilters {
  return { ...EMPTY_FILTERS, q: searchParams.get('q') ?? '', engine: searchParams.get('engine') ?? '' }
}

function isEngineKnown(engineName: string, knownEngineNames: string[] | undefined): boolean {
  return engineName === '' || (knownEngineNames?.includes(engineName) ?? false)
}

export function useListControls() {
  const [searchParams] = useSearchParams()
  const { key: currentLocationKey } = useLocation()
  const knownEngineNames = useKnownEngineNames()
  const [draftFilters, setDraftFilters] = useState<ListFilters>(() => filtersFromUrl(searchParams))
  const [appliedLocationKey, setAppliedLocationKey] = useState(currentLocationKey)

  if (appliedLocationKey !== currentLocationKey) {
    setAppliedLocationKey(currentLocationKey)
    setDraftFilters(filtersFromUrl(searchParams))
  }
  const isDraftEngineUnknown = knownEngineNames !== undefined && !isEngineKnown(draftFilters.engine, knownEngineNames)
  if (isDraftEngineUnknown) {
    setDraftFilters((previousFilters) => ({ ...previousFilters, engine: '' }))
  }

  const filters = useDebouncedValue(draftFilters, FILTER_DEBOUNCE_MILLISECONDS)
  const errors = useMemo(() => validateFilters(filters), [filters])
  const [pageSelection, setPageSelection] = useState({ page: 1, selectedWithFilters: filters })
  const page = pageSelection.selectedWithFilters === filters ? pageSelection.page : 1
  const setPage = useCallback((selectedPage: number) => setPageSelection({ page: selectedPage, selectedWithFilters: filters }), [filters])

  function changeFilter(filterName: keyof ListFilters, value: string) {
    const keptValue = filterName === 'q' ? value : value.trim()
    setDraftFilters((previousFilters) => ({ ...previousFilters, [filterName]: keptValue }))
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
