import { screen } from '@testing-library/react'
import { resetUnauthenticatedGuard } from '@/api/client'
import { initI18n, setLanguage } from '@/i18n'

export const SESSION_OK = { status: 200, body: { status: 'ok', account_name: 'alice', account_role: 'admin' } }

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

// The shell always shows the brand logo; injection tests look for any other image.
export const INJECTED_IMAGE_SELECTOR = 'img[onerror], img:not([src="/crowdsec-logo.png"])'

// Browsers expose a header nested in <main> (the page header) as a plain group,
// but the testing library maps every <header> to the banner role. The
// application banner is the only header outside <main>.
export async function findApplicationHeader(): Promise<HTMLElement> {
  const bannerCandidates = await screen.findAllByRole('banner')
  const applicationHeader = bannerCandidates.find((bannerCandidate) => bannerCandidate.closest('main') === null)
  if (!applicationHeader) {
    throw new Error('no header outside the main region')
  }
  return applicationHeader
}
