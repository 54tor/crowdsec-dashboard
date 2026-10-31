import { vi } from 'vitest'

export interface StubbedResponse {
  status: number
  body?: unknown
}

export type RouteTable = Record<string, StubbedResponse | (() => StubbedResponse)>

export function stubFetch(routes: RouteTable) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const route = routes[`${method} ${String(input)}`]
    if (!route) {
      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 })
    }
    const stubbed = typeof route === 'function' ? route() : route
    return new Response(stubbed.body === undefined ? null : JSON.stringify(stubbed.body), {
      status: stubbed.status,
    })
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}
