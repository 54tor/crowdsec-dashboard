import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
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
const SEARCH_INVALID_MESSAGE = 'The search cannot contain control characters.'
const SEARCH_BUSY_MESSAGE = 'Too many searches are running, try again in a moment.'

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
  })

  it('sendsOnlyTheCompleteTermWhenTypedKeyByKey', async () => {
    const fetchMock = stubFetch({
      ...unfilteredAlertsRoutes(),
      [`GET ${SEARCHED_TABLE_URL}`]: { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/searched-row' })]) },
    })
    await renderAlertsAndWaitForTheFirstRows()

    // delay: null dispatches every keystroke without yielding to the timer queue, so a loaded
    // machine cannot stretch the gap between two keys past the debounce and send a prefix.
    const typingUser = userEvent.setup({ delay: null })
    await typingUser.type(screen.getByLabelText(SEARCH_LABEL), 'ssh-bf')
    await waitForDebounce()

    expect(await screen.findByText('crowdsecurity/searched-row')).toBeInTheDocument()
    // Each keystroke restarts the debounce: every request carrying q carries the whole term,
    // and the 1 and 2 character prefixes never leave the browser.
    const sentSearchTerms = alertsRequestUrls(fetchMock)
      .map((requestedUrl) => new URL(requestedUrl, 'http://example.com').searchParams.get('q'))
      .filter((sentSearchTerm) => sentSearchTerm !== null)
    expect(sentSearchTerms.length).toBeGreaterThan(0)
    expect(sentSearchTerms.every((sentSearchTerm) => sentSearchTerm === 'ssh-bf')).toBe(true)
  })

  it('doesNotQueryWithATermContainingAControlCharacter', async () => {
    const fetchMock = stubFetch(unfilteredAlertsRoutes())
    await renderAlertsAndWaitForTheFirstRows()

    await userEvent.click(screen.getByLabelText(SEARCH_LABEL))
    await userEvent.paste('ssh\tbf')
    await waitForDebounce()

    expect(await screen.findByText(SEARCH_INVALID_MESSAGE)).toBeInTheDocument()
    expect(requestedUrls(fetchMock).some((requestedUrl) => requestedUrl.includes('q='))).toBe(false)
  })

  it('reappliesTheSearchFromTheUrlWhenNavigatingToTheSamePage', async () => {
    const fetchMock = stubFetch({
      ...unfilteredAlertsRoutes(),
      'GET /api/alerts?page=1&per_page=20&q=abc': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/abc-row' })], { window_size: 45, total: 45 }) },
      'GET /api/alerts?page=2&per_page=20&q=abc': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/abc-second-page' })], { page: 2, window_size: 45, total: 45 }) },
      'GET /api/alerts?page=1&per_page=20&q=xyz': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/xyz-row' })]) },
    })
    const { navigateTo } = renderApp('/alerts?q=abc')
    expect(await screen.findByText('crowdsecurity/abc-row')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: en.list.next }))
    expect(await screen.findByText('crowdsecurity/abc-second-page')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(en.filters.scenario), 'crowdsecurity/typed')
    const requestCountBeforeNavigation = fetchMock.mock.calls.length

    await navigateTo('/alerts?q=xyz')
    await waitForDebounce()

    expect(await screen.findByText('crowdsecurity/xyz-row')).toBeInTheDocument()
    expect(screen.getByLabelText(SEARCH_LABEL)).toHaveValue('xyz')
    expect(screen.getByLabelText(en.filters.scenario)).toHaveValue('')
    const tableUrlsAfterNavigation = alertsRequestUrls({ mock: { calls: fetchMock.mock.calls.slice(requestCountBeforeNavigation) } })
      .filter((requestedUrl) => requestedUrl.includes('per_page=20'))
    expect(tableUrlsAfterNavigation).toEqual(['/api/alerts?page=1&per_page=20&q=xyz'])
  })

  // The skip link (href="#main-content") changes only the fragment: in the browser that is a
  // new history entry without state. The typed drafts must survive it.
  it('keepsTheTypedFiltersOnAHashOnlyNavigation', async () => {
    stubFetch({
      ...unfilteredAlertsRoutes(),
      'GET /api/alerts?page=1&per_page=20&q=abc': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/abc-row' })]) },
    })
    const { navigateTo } = renderApp('/alerts?q=abc')
    expect(await screen.findByText('crowdsecurity/abc-row')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(SEARCH_LABEL), 'def')
    await userEvent.type(screen.getByLabelText(en.filters.scenario), 'crowdsecurity/typed')

    await navigateTo('/alerts?q=abc#main-content')

    expect(screen.getByLabelText(SEARCH_LABEL)).toHaveValue('abcdef')
    expect(screen.getByLabelText(en.filters.scenario)).toHaveValue('crowdsecurity/typed')
  })

  it('reappliesThePreviousSearchOnBrowserBack', async () => {
    stubFetch({
      ...unfilteredAlertsRoutes(),
      'GET /api/alerts?page=1&per_page=20&q=abc': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/abc-row' })]) },
      'GET /api/alerts?page=1&per_page=20&q=xyz': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/xyz-row' })]) },
    })
    const { navigateTo, navigateBack } = renderApp('/alerts?q=abc')
    expect(await screen.findByText('crowdsecurity/abc-row')).toBeInTheDocument()
    await navigateTo('/alerts?q=xyz')
    expect(await screen.findByText('crowdsecurity/xyz-row')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(en.filters.scenario), 'crowdsecurity/typed')

    await navigateBack()

    expect(screen.getByLabelText(SEARCH_LABEL)).toHaveValue('abc')
    expect(screen.getByLabelText(en.filters.scenario)).toHaveValue('')
    expect(await screen.findByText('crowdsecurity/abc-row')).toBeInTheDocument()
  })

  it('changingAFilterOnALaterPageRequestsOnlyTheFirstFilteredPage', async () => {
    const fetchMock = stubFetch({
      ...unfilteredAlertsRoutes(),
      [`GET ${UNFILTERED_TABLE_URL}`]: { status: 200, body: makePage([makeAlert()], { window_size: 45, total: 45 }) },
      'GET /api/alerts?page=2&per_page=20': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/second-page' })], { page: 2, window_size: 45, total: 45 }) },
      [`GET ${SEARCHED_TABLE_URL}`]: { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/searched-row' })]) },
    })
    await renderAlertsAndWaitForTheFirstRows()
    await userEvent.click(screen.getByRole('button', { name: en.list.next }))
    expect(await screen.findByText('crowdsecurity/second-page')).toBeInTheDocument()
    const requestCountBeforeTyping = fetchMock.mock.calls.length

    await userEvent.type(screen.getByLabelText(SEARCH_LABEL), 'ssh-bf')
    await waitForDebounce()

    expect(await screen.findByText('crowdsecurity/searched-row')).toBeInTheDocument()
    // The page goes back to 1 together with the debounced filters: the unfiltered
    // first page must not be requested again while the term is being typed.
    const tableUrlsAfterTyping = alertsRequestUrls({ mock: { calls: fetchMock.mock.calls.slice(requestCountBeforeTyping) } })
      .filter((requestedUrl) => requestedUrl.includes('per_page=20'))
    expect(tableUrlsAfterTyping).toEqual([SEARCHED_TABLE_URL])
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
  it('showsTheSearchBusyMessage', async () => {
    const searchBusyResponse = { status: 429, body: { error: 'search_busy' }, headers: { 'Retry-After': '1' } }
    stubFetch({
      ...unfilteredAlertsRoutes(),
      [`GET ${SEARCHED_TABLE_URL}`]: searchBusyResponse,
      [`GET ${SEARCHED_CHART_URL}`]: searchBusyResponse,
    })
    renderApp('/alerts?q=ssh-bf')

    expect(await screen.findByText(SEARCH_BUSY_MESSAGE)).toBeInTheDocument()
  })
})
