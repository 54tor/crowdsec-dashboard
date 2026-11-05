import { screen, within } from '@testing-library/react'
import type userEvent from '@testing-library/user-event'
import { expect } from 'vitest'
import en from '@/i18n/en.json'
import { deferredResponse } from '@/test/pageHarness'

// Three engines: the local one, 'peer' with a usable sidecar (writable) and
// 'bare' without one (read-only). 'disabled-peer' has a sidecar but is disabled,
// so the API would answer 404 engine_not_found: it must not be offered either.
export const ENGINE_NAMES_WITH_SIDECARS = {
  status: 200,
  body: {
    items: [
      { name: 'local', is_local: true, enabled: true, has_sidecar: true },
      { name: 'peer', is_local: false, enabled: true, has_sidecar: true },
      { name: 'bare', is_local: false, enabled: true, has_sidecar: false },
      { name: 'disabled-peer', is_local: false, enabled: false, has_sidecar: true },
    ],
  },
}

// The selector only appears once the engine names are loaded (fail-closed), hence the find.
export async function selectTargetEngine(user: ReturnType<typeof userEvent.setup>, engineName: string, container: HTMLElement = document.body) {
  await user.selectOptions(await within(container).findByLabelText(en.engineTarget.label), engineName)
}

export function offeredEngineNames(): string[] {
  const selector = screen.getByLabelText(en.engineTarget.label) as HTMLSelectElement
  return Array.from(selector.options).map((engineOption) => engineOption.value)
}

// Parses the query string of a requested URL the way the backend does, so a test
// can prove a request carries the engine parameter exactly once (an empty or a
// repeated parameter is a 400 on the API).
export function engineParametersOf(requestedUrl: string): string[] {
  return new URL(requestedUrl, 'http://dashboard.example.com').searchParams.getAll('engine')
}

export function writeRequestUrls(fetchMock: { mock: { calls: unknown[][] } }): string[] {
  return fetchMock.mock.calls
    .filter(([, init]) => {
      const method = (init as RequestInit | undefined)?.method ?? 'GET'
      return method !== 'GET'
    })
    .map(([requestedUrl]) => String(requestedUrl))
}

export function expectEveryWriteToTarget(fetchMock: { mock: { calls: unknown[][] } }, engineName: string) {
  const urls = writeRequestUrls(fetchMock)
  expect(urls.length).toBeGreaterThan(0)
  for (const requestedUrl of urls) {
    expect(engineParametersOf(requestedUrl)).toEqual([engineName])
  }
}

export function expectNoEngineParameterAnywhere(fetchMock: { mock: { calls: unknown[][] } }) {
  for (const [requestedUrl] of fetchMock.mock.calls) {
    expect(String(requestedUrl)).not.toContain('engine=')
  }
}

// Reads the engine named by the "Target engine:" note of a dialog or banner.
export function targetEngineNamedIn(container: HTMLElement): string | null {
  const note = within(container).getByText(en.engineTarget.note, { exact: false })
  return note.querySelector('bdi')?.textContent ?? null
}

type FetchImplementation = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

// Keeps every request to one URL pending until the test settles it, while every
// other request keeps its stubbed answer: a test can then look at the page in the
// window where the new engine's list has not arrived yet.
export function holdRequestsTo(
  fetchMock: { getMockImplementation: () => FetchImplementation | undefined; mockImplementation: (implementation: FetchImplementation) => unknown },
  heldUrl: string,
) {
  const heldResponse = deferredResponse()
  const defaultImplementation = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation(async (input, init) => (String(input) === heldUrl ? heldResponse.promise : defaultImplementation(input, init)))
  return heldResponse
}
