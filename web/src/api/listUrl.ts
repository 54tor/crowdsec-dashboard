import type { ListFilters } from '@/api/types'

export function buildListUrl(path: string, filters: ListFilters, page: number, perPage: number): string {
  const parameters = new URLSearchParams({ page: String(page), per_page: String(perPage) })
  for (const filterName of ['scenario', 'ip', 'since'] as const) {
    if (filters[filterName] !== '') {
      parameters.set(filterName, filters[filterName])
    }
  }
  return `${path}?${parameters.toString()}`
}
