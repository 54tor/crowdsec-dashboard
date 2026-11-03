import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { BIDI_OVERRIDE_SAMPLE, JAVASCRIPT_URL, MALICIOUS_SCENARIO, makeAlert, makeAlertDetail, makePage } from '@/test/fixtures'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { prepareEnglishApp, requestedUrls, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

const FIRST_PAGE_URL = '/api/alerts?page=1&per_page=20'
const SECOND_PAGE_URL = '/api/alerts?page=2&per_page=20'
const CHART_URL = '/api/alerts?page=1&per_page=100'
const DETAIL_URL = '/api/alerts/archive/77'
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }

const ARCHIVED_REMOTE_ALERT = makeAlert({ id: 3, engine: 'edge-1', archive_id: 77, live: false, scenario: 'crowdsecurity/remote-scan' })

function alertRoutes(firstPageBody: unknown, extraRoutes: RouteTable = {}): RouteTable {
  return {
    'GET /api/auth/me': SESSION_OK,
    [`GET ${FIRST_PAGE_URL}`]: { status: 200, body: firstPageBody },
    [`GET ${CHART_URL}`]: { status: 200, body: makePage([]) },
    ...extraRoutes,
  }
}

async function openArchivedDetail(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Details of alert 3 from engine edge-1' }))
  return screen.findByRole('dialog')
}

describe('alerts page with archive', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('affiche le moteur et le badge archivée', async () => {
    stubFetch(alertRoutes(makePage([ARCHIVED_REMOTE_ALERT, makeAlert({ id: 4 })])))
    renderApp('/alerts')

    const table = await screen.findByRole('table', { name: en.alerts.caption })
    const archivedRow = within(table).getByText('crowdsecurity/remote-scan').closest('tr')!
    expect(within(archivedRow).getByText('edge-1')).toBeInTheDocument()
    expect(within(archivedRow).getByText(en.alerts.archivedBadge)).toBeInTheDocument()
    expect(within(table).getByText(en.alerts.liveBadge)).toBeInTheDocument()
  })

  // With the local LAPI down the server still answers 200 from the archive:
  // the banner shows and the archive stays reachable page by page.
  it('affiche le bandeau quand live_status est unavailable', async () => {
    const fetchMock = stubFetch(
      alertRoutes(makePage([ARCHIVED_REMOTE_ALERT], { window_size: 0, total: 45, live_status: 'unavailable' }), {
        [`GET ${SECOND_PAGE_URL}`]: { status: 200, body: makePage([makeAlert({ id: 9, live: false, archive_id: 9, scenario: 'crowdsecurity/page-two' })], { page: 2, window_size: 0, total: 45, live_status: 'unavailable' }) },
      }),
    )
    const user = userEvent.setup()
    renderApp('/alerts')

    expect(await screen.findByText(en.list.liveUnavailable)).toBeInTheDocument()
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    expect(screen.queryByText('0 live entries from the local LAPI')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: en.list.next }))
    expect(await screen.findByText('crowdsecurity/page-two')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(SECOND_PAGE_URL)
  })

  // The page count comes from total, not from the live window size: archive
  // rows past the live window must be reachable.
  it('countsPagesFromTotalNotWindowSize', async () => {
    stubFetch(alertRoutes(makePage([makeAlert()], { window_size: 20, total: 61 })))
    renderApp('/alerts')

    expect(await screen.findByText('Page 1 of 4')).toBeInTheDocument()
    expect(screen.getByText('20 live entries from the local LAPI')).toBeInTheDocument()
    expect(screen.getByText('61 entries in total')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.list.next })).toBeEnabled()
  })

  // total_capped: total is the reachable range (live window + 10 000), shown
  // with a "+" and never paged past.
  it('showsCappedTotalAndStopsAtReachableRange', async () => {
    stubFetch(alertRoutes(makePage([makeAlert()], { window_size: 100, total: 10100, total_capped: true })))
    renderApp('/alerts')

    expect(await screen.findByText('10,100+ entries (only these can be browsed)')).toBeInTheDocument()
    expect(screen.getByText('Page 1 of 505')).toBeInTheDocument()
  })

  it('translatesInvalidRequestForDeepPage', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${FIRST_PAGE_URL}`]: { status: 400, body: { error: 'invalid_request' } },
      [`GET ${CHART_URL}`]: { status: 200, body: makePage([]) },
    })
    renderApp('/alerts')

    expect(await screen.findByText(en.list.invalidRequest)).toBeInTheDocument()
    expect(screen.queryByText('invalid_request')).not.toBeInTheDocument()
  })

  // Two engines can report the same upstream id and uuid (same id space, e.g. a
  // cloned engine): only the engine prefix keeps their React keys distinct.
  it('keepsRowsOfTwoEnginesSharingAnUpstreamId', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    stubFetch(
      alertRoutes(
        makePage([
          makeAlert({ id: 5, engine: 'local', uuid: 'uuid-shared', scenario: 'crowdsecurity/local-five' }),
          makeAlert({ id: 5, engine: 'edge-1', uuid: 'uuid-shared', archive_id: 12, live: false, scenario: 'crowdsecurity/remote-five' }),
        ]),
      ),
    )
    renderApp('/alerts')

    expect(await screen.findByText('crowdsecurity/remote-five')).toBeInTheDocument()
    expect(screen.getByText('crowdsecurity/local-five')).toBeInTheDocument()
    const duplicateKeyWarnings = consoleErrorSpy.mock.calls.filter((loggedArguments) => String(loggedArguments[0]).includes('same key'))
    expect(duplicateKeyWarnings).toHaveLength(0)
    consoleErrorSpy.mockRestore()
  })

  it('offre la suppression pour une alerte vivante du moteur local même archivée', async () => {
    stubFetch(alertRoutes(makePage([makeAlert({ id: 42, uuid: 'uuid-42', archive_id: 8, live: true })])))
    const user = userEvent.setup()
    renderApp('/alerts')

    await user.click(await screen.findByRole('button', { name: 'Delete alert 42' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/also deletes the archived copy/)).toBeInTheDocument()
  })

  it("n'offre pas la suppression pour une alerte d'archive seule", async () => {
    stubFetch(alertRoutes(makePage([makeAlert({ id: 6, engine: 'local', archive_id: 13, live: false }), ARCHIVED_REMOTE_ALERT])))
    renderApp('/alerts')

    await screen.findByText('crowdsecurity/remote-scan')
    expect(screen.queryByRole('button', { name: 'Delete alert 6' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete alert 3' })).not.toBeInTheDocument()
  })

  it('offersDetailsOnlyOnArchivedRows', async () => {
    stubFetch(alertRoutes(makePage([ARCHIVED_REMOTE_ALERT, makeAlert({ id: 4, archive_id: null })])))
    renderApp('/alerts')

    expect(await screen.findByRole('button', { name: 'Details of alert 3 from engine edge-1' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Details of alert 4 from engine local' })).not.toBeInTheDocument()
  })

  it('ne rend jamais une URL javascript: en lien', async () => {
    const detail = makeAlertDetail({
      id: 3,
      message: JAVASCRIPT_URL,
      events: [{ timestamp: '2026-10-31T10:14:30Z', meta: { target_uri: JAVASCRIPT_URL, http_user_agent: MALICIOUS_SCENARIO } }],
    })
    stubFetch(alertRoutes(makePage([ARCHIVED_REMOTE_ALERT]), { [`GET ${DETAIL_URL}`]: { status: 200, body: detail } }))
    const user = userEvent.setup()
    renderApp('/alerts')

    const dialog = await openArchivedDetail(user)

    expect(await within(dialog).findAllByText(JAVASCRIPT_URL)).not.toHaveLength(0)
    expect(within(dialog).getByText(MALICIOUS_SCENARIO)).toBeInTheDocument()
    expect(dialog.querySelector('a')).toBeNull()
    expect(dialog.querySelector('[href]')).toBeNull()
    expect(dialog.querySelector('img')).toBeNull()
  })

  // AppSec alerts get a plain-text summary of the real engine keys above the
  // raw event metadata, which stays listed in full underneath.
  it('showsAppSecSummaryAboveUnchangedEventMeta', async () => {
    const detail = makeAlertDetail({
      id: 3,
      source_kind: 'appsec',
      events: [{ timestamp: '2026-10-31T10:14:30Z', meta: { rule_name: 'crowdsecurity/vpatch-env-access', uri: MALICIOUS_SCENARIO, target_fqdn: 'example.com' } }],
    })
    stubFetch(alertRoutes(makePage([ARCHIVED_REMOTE_ALERT]), { [`GET ${DETAIL_URL}`]: { status: 200, body: detail } }))
    const user = userEvent.setup()
    renderApp('/alerts')

    const dialog = await openArchivedDetail(user)

    const summary = await within(dialog).findByRole('region', { name: en.appsec.summaryTitle })
    expect(within(summary).getByText(en.appsec.fields.rule_name)).toBeInTheDocument()
    expect(within(dialog).getAllByText('crowdsecurity/vpatch-env-access')).toHaveLength(2)
    expect(within(dialog).getByText('rule_name')).toBeInTheDocument()
    expect(dialog.querySelector('img')).toBeNull()
  })

  it('omitsAppSecSummaryForLogAlerts', async () => {
    const detail = makeAlertDetail({ id: 3, source_kind: 'log', events: [{ timestamp: '2026-10-31T10:14:30Z', meta: { target_uri: '/login' } }] })
    stubFetch(alertRoutes(makePage([ARCHIVED_REMOTE_ALERT]), { [`GET ${DETAIL_URL}`]: { status: 200, body: detail } }))
    const user = userEvent.setup()
    renderApp('/alerts')

    const dialog = await openArchivedDetail(user)

    expect(await within(dialog).findByText('/login')).toBeInTheDocument()
    expect(within(dialog).queryByRole('region', { name: en.appsec.summaryTitle })).toBeNull()
  })

  // Events are purged before alerts by retention: the detail explains it
  // instead of showing an error.
  it('showsEmptyStateWhenEventsWerePurged', async () => {
    stubFetch(alertRoutes(makePage([ARCHIVED_REMOTE_ALERT]), { [`GET ${DETAIL_URL}`]: { status: 200, body: makeAlertDetail({ id: 3, events: [] }) } }))
    const user = userEvent.setup()
    renderApp('/alerts')

    const dialog = await openArchivedDetail(user)

    expect(await within(dialog).findByText(en.alertDetail.noEvents)).toBeInTheDocument()
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument()
  })

  it('closesDetailAndReturnsFocusToTrigger', async () => {
    stubFetch(alertRoutes(makePage([ARCHIVED_REMOTE_ALERT]), { [`GET ${DETAIL_URL}`]: { status: 200, body: makeAlertDetail({ id: 3 }) } }))
    const user = userEvent.setup()
    renderApp('/alerts')

    const dialog = await openArchivedDetail(user)
    await user.click(within(dialog).getByRole('button', { name: en.alertDetail.close }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Details of alert 3 from engine edge-1' })).toHaveFocus()
  })

  it('isolatesBidiOverrideInFreeTextCells', async () => {
    stubFetch(alertRoutes(makePage([makeAlert({ scenario: BIDI_OVERRIDE_SAMPLE, message: BIDI_OVERRIDE_SAMPLE, machine_id: BIDI_OVERRIDE_SAMPLE })])))
    renderApp('/alerts')

    const table = await screen.findByRole('table', { name: en.alerts.caption })
    const isolatedCells = Array.from(table.querySelectorAll('bdi')).filter((isolatedText) => isolatedText.textContent === BIDI_OVERRIDE_SAMPLE)
    expect(isolatedCells).toHaveLength(3)
  })

  it('filtre par moteur pour un compte read_only', async () => {
    const filteredUrl = '/api/alerts?page=1&per_page=20&engine=edge-1'
    const fetchMock = stubFetch(
      alertRoutes(makePage([makeAlert()]), {
        'GET /api/auth/me': READ_ONLY_SESSION,
        'GET /api/engines/names': { status: 200, body: { items: [{ name: 'local', is_local: true, enabled: true }, { name: 'edge-1', is_local: false, enabled: true }] } },
        [`GET ${filteredUrl}`]: { status: 200, body: makePage([ARCHIVED_REMOTE_ALERT]) },
        'GET /api/alerts?page=1&per_page=100&engine=edge-1': { status: 200, body: makePage([]) },
      }),
    )
    const user = userEvent.setup()
    renderApp('/alerts')

    const engineSelect = await screen.findByLabelText(en.filters.engine)
    await screen.findByRole('option', { name: 'edge-1' })
    await user.selectOptions(engineSelect, 'edge-1')

    expect(await screen.findByText('crowdsecurity/remote-scan')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(filteredUrl)
    expect(screen.queryByText(/live entries from the local LAPI/)).not.toBeInTheDocument()
    expect(requestsTo(fetchMock, 'GET', '/api/engines/names')).not.toHaveLength(0)
  })
})
