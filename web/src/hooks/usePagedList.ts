import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/api/client'
import { buildListUrl } from '@/api/listUrl'
import type { ListFilters, Page } from '@/api/types'

export const PAGE_SIZE = 20

export function usePagedList<Item>(
  resource: 'alerts' | 'decisions',
  filters: ListFilters,
  page: number,
  perPage: number,
  isEnabled: boolean,
) {
  return useQuery({
    queryKey: [resource, filters, page, perPage],
    queryFn: () => apiFetch<Page<Item>>(buildListUrl(`/api/${resource}`, filters, page, perPage)),
    placeholderData: keepPreviousData,
    enabled: isEnabled,
  })
}
