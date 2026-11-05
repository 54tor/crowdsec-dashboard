import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { makeAlert, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestedUrls, SESSION_OK, waitForDebounce } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

// Exact en.json values of the new keys, quoted so a missing key fails the test.
const SEARCH_LABEL = 'Search'
const SEARCH_TOO_SHORT_MESSAGE = 'Enter at least 3 characters.'
const SEARCH_TIMEOUT_MESSAGE = 'The search took longer than 5 seconds. Narrow it down.'
const CLEAR_SEARCH_LABEL = 'Clear the search'

const UNFILTERED_TABLE_URL = '/api/alerts?page=1&per_page=20'
const UNFILTERED_CHART_URL = '/api/alerts?page=1&per_page=100'
const SEARCHED_TABLE_URL = '/api/alerts?page=1&per_page=20&q=ssh-bf'
const SEARCHED_CHART_URL = '/api/alerts?page=1&per_page=100&q=ssh-bf'

const ENGINE_NAMES_BODY = { items: [{ name: 'local', is_local: true, enabled: true }, { name: 'peer-a', is_local: false, enabled: true }] }

function unfilteredAlertsRoutes() {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines/names': { status: 200, body: ENGINE_NAMES_BODY },
    [`GET ${UNFILTERED_TABLE_URL}`]: { status: 200, body: makePage([makeAlert()]) },
    [`GET ${UNFILTERED_CHART_URL}`]: { status: 200, body: makePage([makeAlert()]) },
  }
}

function alertsRequestUrls(fetchMock: { mock: { calls: unknown[][] } }): string[] {
  return requestedUrls(fetchMock).filter((requestedUrl) => requestedUrl.startsWith('/api/alerts?'))
}

async function renderAlertsAndWaitForTheFirstRows() {
  const renderResult = renderApp('/alerts')
  await screen.findByText('crowdsecurity/ssh-bf', { selector: 'td bdi' })
  return renderResult
}

describe('alerts search', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('sendsTheTrimmedSearchTermAfterTheDebounce', async () => {
    const fetchMock = stubFetch({
      ...unfilteredAlertsRoutes(),
      [`GET ${SEARCHED_TABLE_URL}`]: { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/searched-row' })]) },
    })
    await renderAlertsAndWaitForTheFirstRows()

    await userEvent.type(screen.getByLabelText(SEARCH_LABEL), '  ssh-bf ')
    await waitForDebounce()

    expect(await screen.findByText('crowdsecurity/searched-row')).toBeInTheDocument()
    const alertsUrls = alertsRequestUrls(fetchMock)
    expect(alertsUrls).toContain(SEARCHED_TABLE_URL)
    expect(alertsUrls).toContain(SEARCHED_CHART_URL)
    // Each keystroke restarts the debounce: no partial term may reach the server.
    const partialTermUrls = alertsUrls.filter((requestedUrl) => requestedUrl.endsWith('q=ss') || requestedUrl.endsWith('q=ssh') || requestedUrl.includes('q=ss&') || requestedUrl.includes('q=ssh&'))
    expect(partialTermUrls).toEqual([])
  })

  it('doesNotQueryWithATermShorterThanThreeCharacters', async () => {
    const fetchMock = stubFetch(unfilteredAlertsRoutes())
    await renderAlertsAndWaitForTheFirstRows()

    await userEvent.type(screen.getByLabelText(SEARCH_LABEL), 'ab')
    await waitForDebounce()

    expect(await screen.findByText(SEARCH_TOO_SHORT_MESSAGE)).toBeInTheDocument()
    expect(screen.getByLabelText(SEARCH_LABEL)).toHaveAttribute('aria-invalid', 'true')
    expect(requestedUrls(fetchMock).some((requestedUrl) => requestedUrl.includes('q='))).toBe(false)
  })

  it('readsTheInitialSearchAndEngineFromTheUrl', async () => {
    const fetchMock = stubFetch({
      ...unfilteredAlertsRoutes(),
      'GET /api/alerts?page=1&per_page=20&q=198.51&engine=peer-a': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/peer-row' })]) },
    })
    renderApp('/alerts?q=198.51&engine=peer-a')

    expect(await screen.findByText('crowdsecurity/peer-row')).toBeInTheDocument()
    expect(screen.getByLabelText(SEARCH_LABEL)).toHaveValue('198.51')
    const firstAlertsUrl = alertsRequestUrls(fetchMock)[0]
    expect(firstAlertsUrl).toContain('q=198.51')
    expect(firstAlertsUrl).toContain('engine=peer-a')
  })

  it('ignoresAnEngineFromTheUrlThatIsNotInTheEngineList', async () => {
    const fetchMock = stubFetch(unfilteredAlertsRoutes())
    renderApp('/alerts?engine=unknown-peer')

    expect(await screen.findByText('crowdsecurity/ssh-bf', { selector: 'td bdi' })).toBeInTheDocument()
    expect(requestedUrls(fetchMock).some((requestedUrl) => requestedUrl.includes('engine='))).toBe(false)
  })

  it('typingDoesNotRewriteTheUrl', async () => {
    stubFetch(unfilteredAlertsRoutes())
    const { visitedLocations } = await renderAlertsAndWaitForTheFirstRows()

    await userEvent.type(screen.getByLabelText(SEARCH_LABEL), 'ssh-bf')
    await waitForDebounce()

    expect(visitedLocations).toEqual(['/alerts'])
  })

  it('clearsTheSearchWithTheClearButton', async () => {
    const fetchMock = stubFetch(unfilteredAlertsRoutes())
    renderApp('/alerts?q=198.51')
    const searchField = await screen.findByLabelText(SEARCH_LABEL)
    expect(searchField).toHaveAttribute('type', 'search')
    expect(searchField).toHaveAttribute('autocomplete', 'off')

    await userEvent.click(screen.getByRole('button', { name: CLEAR_SEARCH_LABEL }))
    await waitForDebounce()

    expect(searchField).toHaveValue('')
    expect(searchField).toHaveFocus()
    expect(await screen.findByText('crowdsecurity/ssh-bf', { selector: 'td bdi' })).toBeInTheDocument()
    expect(alertsRequestUrls(fetchMock)).toContain(UNFILTERED_TABLE_URL)
    expect(screen.queryByRole('button', { name: CLEAR_SEARCH_LABEL })).toBeNull()
  })

  it('showsTheSearchTimeoutMessage', async () => {
    const searchTimeoutResponse = { status: 503, body: { error: 'search_timeout' } }
    stubFetch({
      ...unfilteredAlertsRoutes(),
      [`GET ${SEARCHED_TABLE_URL}`]: searchTimeoutResponse,
      [`GET ${SEARCHED_CHART_URL}`]: searchTimeoutResponse,
    })
    renderApp('/alerts?q=ssh-bf')

    expect(await screen.findByText(SEARCH_TIMEOUT_MESSAGE)).toBeInTheDocument()
  })
})
