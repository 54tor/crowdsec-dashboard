import { useTranslation } from 'react-i18next'
import type { AccountRole } from '@/auth/AuthContext'
import type { Alert, Decision, Page } from '@/api/types'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useKnownEngineNames } from '@/hooks/useKnownEngineNames'
import { EMPTY_FILTERS } from '@/hooks/useListControls'
import { usePagedList } from '@/hooks/usePagedList'
import { validateFilters } from '@/lib/filterValidation'
import { PALETTE_DEBOUNCE_MILLISECONDS, PALETTE_RESULTS_PER_CATEGORY } from '@/lib/paletteTargets'
import { matchesSearchText } from '@/lib/searchText'
import { visibleNavItems, type NavItem } from '@/routes'

interface RecordResults {
  alerts: Alert[]
  decisions: Decision[]
  recordSearchTerm: string
  isSearchingRecords: boolean
  hasRecordSearchFailed: boolean
}

export interface PaletteResults extends RecordResults {
  pages: NavItem[]
  engineNames: string[]
}

interface RecordQueryState<Item> {
  data?: Page<Item>
  isFetching: boolean
  isError: boolean
  isPlaceholderData: boolean
}

export function isRecordSearchTermUsable(searchTerm: string): boolean {
  const hasSearchError = validateFilters({ scenario: '', ip: '', since: '', q: searchTerm }).q !== undefined
  return searchTerm !== '' && !hasSearchError
}

function firstResults<Item>(items: readonly Item[] | undefined): Item[] {
  return (items ?? []).slice(0, PALETTE_RESULTS_PER_CATEGORY)
}

function currentResults<Item>(recordQuery: RecordQueryState<Item>): Item[] {
  if (recordQuery.isPlaceholderData || recordQuery.isError) {
    return []
  }
  return firstResults(recordQuery.data?.items)
}

function useRecordResults(searchText: string): RecordResults {
  const typedSearchTerm = searchText.trim()
  const debouncedSearchTerm = useDebouncedValue(typedSearchTerm, PALETTE_DEBOUNCE_MILLISECONDS)
  const isSearchTermLongEnough = isRecordSearchTermUsable(debouncedSearchTerm)
  const searchFilters = { ...EMPTY_FILTERS, q: debouncedSearchTerm }
  const alertsQuery = usePagedList<Alert>('alerts', searchFilters, 1, PALETTE_RESULTS_PER_CATEGORY, isSearchTermLongEnough)
  const decisionsQuery = usePagedList<Decision>('decisions', searchFilters, 1, PALETTE_RESULTS_PER_CATEGORY, isSearchTermLongEnough)
  const isDebouncePending = typedSearchTerm !== debouncedSearchTerm && isRecordSearchTermUsable(typedSearchTerm)
  if (!isSearchTermLongEnough) {
    return { alerts: [], decisions: [], recordSearchTerm: debouncedSearchTerm, isSearchingRecords: isDebouncePending, hasRecordSearchFailed: false }
  }
  return {
    alerts: currentResults(alertsQuery),
    decisions: currentResults(decisionsQuery),
    recordSearchTerm: debouncedSearchTerm,
    isSearchingRecords: isDebouncePending || alertsQuery.isFetching || decisionsQuery.isFetching,
    hasRecordSearchFailed: alertsQuery.isError || decisionsQuery.isError,
  }
}

export function usePaletteResults(searchText: string, accountRole: AccountRole | null): PaletteResults {
  const { t } = useTranslation()
  const knownEngineNames = useKnownEngineNames()
  const recordResults = useRecordResults(searchText)
  const matchingPages = visibleNavItems(accountRole).filter((navItem) => matchesSearchText(searchText, [t(navItem.labelKey)]))
  const matchingEngineNames = (knownEngineNames ?? []).filter((engineName) => matchesSearchText(searchText, [engineName]))
  return {
    pages: firstResults(matchingPages),
    engineNames: firstResults(matchingEngineNames),
    ...recordResults,
  }
}
