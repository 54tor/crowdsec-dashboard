import { keepPreviousData, useQuery, type UseQueryResult } from '@tanstack/react-query'
import { apiFetch } from '@/api/client'
import type { Page } from '@/api/types'
import { PAGE_SIZE } from '@/hooks/usePagedList'

export interface AuditEvent {
  id: number
  created_at: string
  account: string | null
  action: string
  target: string | null
  client_ip: string | null
}

export interface AuditFilters {
  action: string
  account: string
  since: string
  q: string
}

const AUDIT_PATH = '/api/audit'
const AUDIT_FILTER_NAMES = ['action', 'account', 'since', 'q'] as const

export function buildAuditUrl(filters: AuditFilters, page: number, perPage: number): string {
  const parameters = new URLSearchParams({ page: String(page), per_page: String(perPage) })
  for (const filterName of AUDIT_FILTER_NAMES) {
    const trimmedValue = filters[filterName].trim()
    if (trimmedValue !== '') {
      parameters.set(filterName, trimmedValue)
    }
  }
  return `${AUDIT_PATH}?${parameters.toString()}`
}

export function useAuditList(filters: AuditFilters, page: number, isEnabled: boolean): UseQueryResult<Page<AuditEvent>> {
  return useQuery({
    queryKey: ['audit', filters, page],
    queryFn: ({ signal }) => apiFetch<Page<AuditEvent>>(buildAuditUrl(filters, page, PAGE_SIZE), { signal }),
    placeholderData: keepPreviousData,
    enabled: isEnabled,
  })
}
