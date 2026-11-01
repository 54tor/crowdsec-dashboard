import type { ListFilters } from '@/api/types'

export function buildListUrl(path: string, filters: ListFilters, page: number, perPage: number, includeExpired = false): string {
  const parameters = new URLSearchParams({ page: String(page), per_page: String(perPage) })
  for (const filterName of ['scenario', 'ip', 'since', 'engine'] as const) {
    if (filters[filterName] !== '') {
      parameters.set(filterName, filters[filterName])
    }
  }
  if (includeExpired) {
    parameters.set('include_expired', 'true')
  }
  return `${path}?${parameters.toString()}`
}
