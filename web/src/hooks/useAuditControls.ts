import { useCallback, useMemo, useState } from 'react'
import type { AuditFilters } from '@/api/auditApi'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { FILTER_DEBOUNCE_MILLISECONDS } from '@/hooks/useListControls'
import { validateAuditFilters } from '@/lib/auditFilterValidation'

const EMPTY_AUDIT_FILTERS: AuditFilters = { action: '', account: '', since: '', q: '' }

export function useAuditControls() {
  const [draftFilters, setDraftFilters] = useState<AuditFilters>(EMPTY_AUDIT_FILTERS)
  const filters = useDebouncedValue(draftFilters, FILTER_DEBOUNCE_MILLISECONDS)
  const errors = useMemo(() => validateAuditFilters(filters), [filters])
  const [pageSelection, setPageSelection] = useState({ page: 1, selectedWithFilters: filters })
  const page = pageSelection.selectedWithFilters === filters ? pageSelection.page : 1
  const setPage = useCallback((selectedPage: number) => setPageSelection({ page: selectedPage, selectedWithFilters: filters }), [filters])

  function changeFilter(filterName: keyof AuditFilters, value: string) {
    const keptValue = filterName === 'q' ? value : value.trim()
    setDraftFilters((previousFilters) => ({ ...previousFilters, [filterName]: keptValue }))
  }

  const isValid = Object.keys(errors).length === 0
  const activeFilterCount = Object.values(draftFilters).filter((filterValue) => filterValue.trim() !== '').length

  return { activeFilterCount, draftFilters, filters, errors, isValid, page, setPage, changeFilter }
}
