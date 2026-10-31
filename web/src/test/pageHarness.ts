import { resetUnauthenticatedGuard } from '@/api/client'
import { initI18n, setLanguage } from '@/i18n'

export const SESSION_OK = { status: 200, body: { status: 'ok' } }

export const DEBOUNCE_WAIT_MILLISECONDS = 500

export async function prepareEnglishApp(): Promise<void> {
  resetUnauthenticatedGuard()
  await initI18n()
  await setLanguage('en')
}

export function waitForDebounce(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MILLISECONDS))
}

export function requestedUrls(fetchMock: { mock: { calls: unknown[][] } }): string[] {
  return fetchMock.mock.calls.map(([requestedUrl]) => String(requestedUrl))
}

export function requestsTo(fetchMock: { mock: { calls: unknown[][] } }, method: string, url: string): RequestInit[] {
  return fetchMock.mock.calls
    .filter(([requestedUrl, init]) => String(requestedUrl) === url && ((init as RequestInit | undefined)?.method ?? 'GET') === method)
    .map(([, init]) => (init ?? {}) as RequestInit)
}

export function slowResponse(status: number, body: unknown, delayMilliseconds: number): Promise<Response> {
  return new Promise((resolve) => {
    setTimeout(() => resolve(new Response(JSON.stringify(body), { status })), delayMilliseconds)
  })
}

export function deferredResponse() {
  let resolveResponse!: (response: Response) => void
  const promise = new Promise<Response>((resolve) => {
    resolveResponse = resolve
  })
  return {
    promise,
    settle: (status: number, body: unknown) => resolveResponse(new Response(JSON.stringify(body), { status })),
  }
}

export function holdPostRequests(fetchMock: { getMockImplementation: () => ((input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) | undefined; mockImplementation: (implementation: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) => unknown }) {
  const heldResponse = deferredResponse()
  const defaultImplementation = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation(async (input, init) => (init?.method === 'POST' || init?.method === 'DELETE' ? heldResponse.promise : defaultImplementation(input, init)))
  return heldResponse
}
