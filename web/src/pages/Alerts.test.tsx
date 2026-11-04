import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { MALICIOUS_SCENARIO, makeAlert, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { INJECTED_IMAGE_SELECTOR, prepareEnglishApp, requestedUrls, SESSION_OK, waitForDebounce } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

const FIRST_PAGE_URL = '/api/alerts?page=1&per_page=20'
const SECOND_PAGE_URL = '/api/alerts?page=2&per_page=20'
const CHART_URL = '/api/alerts?page=1&per_page=100'

function alertsRoutes(firstPageBody: unknown) {
  return {
    'GET /api/auth/me': SESSION_OK,
    [`GET ${FIRST_PAGE_URL}`]: { status: 200, body: firstPageBody },
    [`GET ${CHART_URL}`]: { status: 200, body: makePage([makeAlert()]) },
  }
}

describe('alerts page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('alertsTableRequestsNextPageFromServer', async () => {
    const fetchMock = stubFetch({
      ...alertsRoutes(makePage([makeAlert({ id: 1, scenario: 'crowdsecurity/first-page' })], { window_size: 45 })),
      [`GET ${SECOND_PAGE_URL}`]: {
        status: 200,
        body: makePage([makeAlert({ id: 2, scenario: 'crowdsecurity/second-page' })], { page: 2, window_size: 45 }),
      },
    })
    renderApp('/alerts')
    expect(await screen.findByText('crowdsecurity/first-page')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: en.list.next }))

    expect(await screen.findByText('crowdsecurity/second-page')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(SECOND_PAGE_URL)
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument()
  })

  it('disablesPaginationControlsAtBounds', async () => {
    stubFetch({
      ...alertsRoutes(makePage([makeAlert()], { window_size: 20 })),
    })
    renderApp('/alerts')
    await screen.findByText('crowdsecurity/ssh-bf', { selector: 'td bdi' })

    expect(screen.getByRole('button', { name: en.list.previous })).toBeDisabled()
    expect(screen.getByRole('button', { name: en.list.next })).toBeDisabled()
  })

  it('showsTruncationNoticeWhenWindowMayBeTruncated', async () => {
    stubFetch(alertsRoutes(makePage([makeAlert()], { window_size: 100, may_be_truncated: true })))
    renderApp('/alerts')

    expect(await screen.findByText('The live part holds only the 100 most recent entries of the local LAPI; older entries are listed from the archive.')).toBeInTheDocument()
  })

  it('showsEmptyStateWhenNoAlertMatches', async () => {
    stubFetch(alertsRoutes(makePage([], { window_size: 0 })))
    renderApp('/alerts')

    expect(await screen.findByText(en.alerts.empty)).toBeInTheDocument()
  })

  it('showsTranslatedMessageWhenServerFails', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${FIRST_PAGE_URL}`]: { status: 502, body: { error: 'lapi_unavailable' } },
      [`GET ${CHART_URL}`]: { status: 502, body: { error: 'lapi_unavailable' } },
    })
    renderApp('/alerts')

    expect((await screen.findAllByText(en.errors.lapi_unavailable)).length).toBeGreaterThan(0)
  })

  it('doesNotFireRequestForInvalidIpFilter', async () => {
    const fetchMock = stubFetch(alertsRoutes(makePage([makeAlert()])))
    renderApp('/alerts')
    await screen.findByText('crowdsecurity/ssh-bf', { selector: 'td bdi' })
    const callsBeforeTyping = fetchMock.mock.calls.length

    await userEvent.type(screen.getByLabelText(en.filters.ip), '1.2.3.4/33')
    await waitForDebounce()

    expect(await screen.findByText(en.filters.ipInvalid)).toBeInTheDocument()
    expect(fetchMock.mock.calls.length).toBe(callsBeforeTyping)
    expect(requestedUrls(fetchMock).some((requestedUrl) => requestedUrl.includes('ip='))).toBe(false)
  })

  it('sendsValidIpFilterToServerAfterDebounce', async () => {
    const filteredUrl = '/api/alerts?page=1&per_page=20&ip=203.0.113.7'
    const fetchMock = stubFetch({
      ...alertsRoutes(makePage([makeAlert()])),
      [`GET ${filteredUrl}`]: { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/filtered-row' })]) },
    })
    renderApp('/alerts')
    await screen.findByText('crowdsecurity/ssh-bf', { selector: 'td bdi' })

    await userEvent.type(screen.getByLabelText(en.filters.ip), '203.0.113.7')

    expect(await screen.findByText('crowdsecurity/filtered-row')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(filteredUrl)
  })

  it('rendersAttackerControlledScenarioAsText', async () => {
    stubFetch(alertsRoutes(makePage([makeAlert({ scenario: MALICIOUS_SCENARIO, message: MALICIOUS_SCENARIO })])))
    const { container } = renderApp('/alerts')

    const table = await screen.findByRole('table', { name: en.alerts.caption })
    expect(within(table).getAllByText(MALICIOUS_SCENARIO).length).toBe(2)
    expect(container.querySelector(INJECTED_IMAGE_SELECTOR)).toBeNull()
  })

  it('affiche le badge AppSec', async () => {
    stubFetch(
      alertsRoutes(
        makePage([
          makeAlert({ id: 1, scenario: 'crowdsecurity/vpatch-env-access', source_kind: 'appsec' }),
          makeAlert({ id: 2, scenario: 'crowdsecurity/ssh-bf', source_kind: 'log' }),
        ]),
      ),
    )
    renderApp('/alerts')

    const table = await screen.findByRole('table', { name: en.alerts.caption })
    const appSecRow = within(table).getByText('crowdsecurity/vpatch-env-access').closest('tr') as HTMLElement
    const logRow = within(table).getByText('crowdsecurity/ssh-bf').closest('tr') as HTMLElement
    expect(within(appSecRow).getByText(en.alerts.appSecBadge)).toBeInTheDocument()
    expect(within(logRow).queryByText(en.alerts.appSecBadge)).toBeNull()
  })

  // The origin filter is sent as source_kind; "all" sends no parameter at all,
  // which the default FIRST_PAGE_URL of every other test already proves.
  it('filtre par origine AppSec', async () => {
    const appSecUrl = '/api/alerts?page=1&per_page=20&source_kind=appsec'
    const logUrl = '/api/alerts?page=1&per_page=20&source_kind=log'
    const fetchMock = stubFetch({
      ...alertsRoutes(makePage([makeAlert()])),
      [`GET ${appSecUrl}`]: { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/appsec-only', source_kind: 'appsec' })]) },
      [`GET ${logUrl}`]: { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/log-only', source_kind: 'log' })]) },
    })
    renderApp('/alerts')
    await screen.findByText('crowdsecurity/ssh-bf', { selector: 'td bdi' })

    await userEvent.click(screen.getByRole('radio', { name: en.filters.originAppSec }))
    expect(await screen.findByText('crowdsecurity/appsec-only')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(appSecUrl)

    await userEvent.click(screen.getByRole('radio', { name: en.filters.originLogs }))
    expect(await screen.findByText('crowdsecurity/log-only')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(logUrl)
  })

  it('sendsVisitorToLoginWhenDataCallIsUnauthenticated', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${FIRST_PAGE_URL}`]: { status: 401, body: { error: 'unauthenticated' } },
      [`GET ${CHART_URL}`]: { status: 401, body: { error: 'unauthenticated' } },
    })
    const { visitedPaths } = renderApp('/alerts')

    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    expect(visitedPaths).toEqual(['/alerts', '/login'])
  })
})
