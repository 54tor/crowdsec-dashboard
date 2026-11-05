import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { INJECTED_IMAGE_SELECTOR, prepareEnglishApp, requestedUrls, SESSION_OK, waitForDebounce } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

// Exact en.json values of the new keys, quoted so a missing key fails the test.
const AUDIT_TITLE = 'Audit log'
const AUDIT_EMPTY_MESSAGE = 'No event matches.'
const ACTION_LABEL = 'Action'
const ACCOUNT_LABEL = 'Account'
const SINCE_LABEL = 'Since'
const SEARCH_LABEL = 'Search'
const TARGET_HIDDEN_EXPLANATION = 'Hidden on purpose for failed sign-ins'
const TARGET_UNAVAILABLE_PLACEHOLDER = 'Not available'
const SEARCH_TOO_SHORT_MESSAGE = 'Enter at least 3 characters.'
const SEARCH_INVALID_MESSAGE = 'The search cannot contain control characters.'
const SEARCH_BUSY_MESSAGE = 'Too many searches are running, try again in a moment.'
const PHONE_VIEWPORT_WIDTH_IN_PIXELS = 390
const SECOND_AUDIT_PAGE_URL = '/api/audit?page=2&per_page=20'
const FIRST_PAGE_FILTERED_ON_ACTION_URL = '/api/audit?page=1&per_page=20&action=login_failure'

const READ_ONLY_SESSION = { status: 200, body: { status: 'ok', account_name: 'bob', account_role: 'read_only' } }
const UNFILTERED_AUDIT_URL = '/api/audit?page=1&per_page=20'
const FILTERED_AUDIT_URL = '/api/audit?page=1&per_page=20&action=login_failure&account=alice&since=24h&q=peer'

interface AuditEventFixture {
  id: number
  created_at: string
  account: string | null
  action: string
  target: string | null
  client_ip: string | null
}

function makeAuditEvent(overrides: Partial<AuditEventFixture> = {}): AuditEventFixture {
  return {
    id: 1,
    created_at: '2026-11-05T10:15:42Z',
    account: 'alice',
    action: 'engine_create',
    target: 'peer-a',
    client_ip: '198.51.100.7',
    ...overrides,
  }
}

function auditRoutes(auditEvents: AuditEventFixture[], extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    [`GET ${UNFILTERED_AUDIT_URL}`]: { status: 200, body: makePage(auditEvents) },
    ...extraRoutes,
  }
}

function auditRequestUrls(fetchMock: { mock: { calls: unknown[][] } }): string[] {
  return requestedUrls(fetchMock).filter((requestedUrl) => requestedUrl.startsWith('/api/audit'))
}

describe('audit log page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('readOnlyAccountIsKeptAwayFromTheAuditPage', async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/me': READ_ONLY_SESSION,
      'GET /api/alerts?page=1&per_page=20': { status: 200, body: makePage([]) },
      'GET /api/alerts?page=1&per_page=100': { status: 200, body: makePage([]) },
    })
    renderApp('/audit')

    await screen.findByRole('heading', { name: en.alerts.title })
    expect(screen.queryByRole('heading', { name: AUDIT_TITLE })).not.toBeInTheDocument()
    expect(auditRequestUrls(fetchMock)).toEqual([])
  })

  it('listsEventsInServerOrder', async () => {
    stubFetch(
      auditRoutes([
        makeAuditEvent({ id: 3, action: 'account_create', target: 'carol' }),
        makeAuditEvent({ id: 2, action: 'login_failure', account: null, target: null, client_ip: null }),
        makeAuditEvent({ id: 1, action: 'engine_create', target: 'peer-a' }),
      ]),
    )
    renderApp('/audit')

    expect(await screen.findByRole('heading', { name: AUDIT_TITLE })).toBeInTheDocument()
    await screen.findByText('account_create', { selector: 'td bdi' })
    const displayedActions = screen.getAllByRole('row').slice(1).map((tableRow) => within(tableRow).getAllByRole('cell')[2].textContent)
    expect(displayedActions).toEqual(['account_create', 'login_failure', 'engine_create'])
    const loginFailureRow = screen.getAllByRole('row')[2]
    expect(within(loginFailureRow).getByText(en.audit.noAccount)).toBeInTheDocument()
    expect(within(loginFailureRow).getByText(en.audit.noTarget)).toBeInTheDocument()
    expect(within(loginFailureRow).getByText(en.audit.noClientIp)).toBeInTheDocument()
  })

  it('sendsActionAccountSinceAndSearchFilters', async () => {
    const fetchMock = stubFetch(
      auditRoutes([makeAuditEvent()], {
        [`GET ${FILTERED_AUDIT_URL}`]: { status: 200, body: makePage([makeAuditEvent({ id: 9, action: 'login_failure', target: null })]) },
      }),
    )
    const user = userEvent.setup()
    renderApp('/audit')
    await screen.findByText('engine_create', { selector: 'td bdi' })

    await user.type(screen.getByLabelText(ACTION_LABEL), 'login_failure')
    await user.type(screen.getByLabelText(ACCOUNT_LABEL), 'alice')
    await user.type(screen.getByLabelText(SINCE_LABEL), '24h')
    await user.type(screen.getByLabelText(SEARCH_LABEL), 'peer')
    await waitForDebounce()

    expect(await screen.findByText('login_failure', { selector: 'td bdi' })).toBeInTheDocument()
    expect(auditRequestUrls(fetchMock)).toContain(FILTERED_AUDIT_URL)
  })

  it('doesNotQueryWithAnInvalidActionAndExplainsTheRule', async () => {
    const fetchMock = stubFetch(auditRoutes([makeAuditEvent()]))
    const user = userEvent.setup()
    renderApp('/audit')
    await screen.findByText('engine_create', { selector: 'td bdi' })

    await user.type(screen.getByLabelText(ACTION_LABEL), 'Login-Failure')
    await waitForDebounce()

    expect(await screen.findByText(en.audit.filters.actionInvalid)).toBeInTheDocument()
    const actionRequests = auditRequestUrls(fetchMock).filter((requestedUrl) => requestedUrl.includes('action='))
    expect(actionRequests).toEqual([])
  })

  it('rendersHostileTargetAsText', async () => {
    const hostileTarget = `<img src=x onerror=alert(1)>${'a'.repeat(300)}`
    stubFetch(auditRoutes([makeAuditEvent({ target: hostileTarget })]))
    const { container } = renderApp('/audit')

    const targetText = await screen.findByText(hostileTarget)
    expect(targetText.tagName).toBe('BDI')
    expect(targetText).toHaveAttribute('title', hostileTarget)
    expect(container.querySelector(INJECTED_IMAGE_SELECTOR)).toBeNull()
  })

  it('showsTheExplicitEmptyMessage', async () => {
    stubFetch(auditRoutes([]))
    renderApp('/audit')

    expect(await screen.findByText(AUDIT_EMPTY_MESSAGE)).toBeInTheDocument()
  })

  it('showsTheSearchTimeoutMessage', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${UNFILTERED_AUDIT_URL}`]: { status: 503, body: { error: 'search_timeout' } },
    })
    renderApp('/audit')

    expect(await screen.findByText(en.list.searchTimeout)).toBeInTheDocument()
  })

  it('showsTheSearchBusyMessage', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${UNFILTERED_AUDIT_URL}`]: { status: 429, body: { error: 'search_busy' }, headers: { 'Retry-After': '1' } },
    })
    renderApp('/audit')

    expect(await screen.findByText(SEARCH_BUSY_MESSAGE)).toBeInTheDocument()
  })

  // The first request is held open; typing a search replaces it, so TanStack must abort it
  // through the signal handed to fetch, and the aborted request must not surface as an error.
  it('cancelsTheAbandonedRequestWithoutShowingAnError', async () => {
    const searchedAuditUrl = '/api/audit?page=1&per_page=20&q=peer'
    const fetchMock = stubFetch(auditRoutes([], { [`GET ${searchedAuditUrl}`]: { status: 200, body: makePage([makeAuditEvent()]) } }))
    const defaultImplementation = fetchMock.getMockImplementation() as (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    const heldRequest: { signal?: AbortSignal } = {}
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) !== UNFILTERED_AUDIT_URL) {
        return defaultImplementation(input, init)
      }
      return new Promise<Response>((_resolve, reject) => {
        heldRequest.signal = init?.signal ?? undefined
        heldRequest.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
      })
    })
    const user = userEvent.setup()
    renderApp('/audit')
    await screen.findByLabelText(SEARCH_LABEL)

    await user.type(screen.getByLabelText(SEARCH_LABEL), 'peer')
    await waitForDebounce()

    expect(await screen.findByText('engine_create', { selector: 'td bdi' })).toBeInTheDocument()
    expect(heldRequest.signal?.aborted).toBe(true)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('explainsWhyTheTargetOfAFailedSignInIsHidden', async () => {
    stubFetch(auditRoutes([makeAuditEvent({ action: 'login_failure', account: null, target: null })]))
    renderApp('/audit')

    const explanation = await screen.findByText(TARGET_HIDDEN_EXPLANATION)
    expect(explanation).toHaveClass('sr-only')
    expect(screen.getByTitle(TARGET_HIDDEN_EXPLANATION)).toHaveTextContent(TARGET_UNAVAILABLE_PLACEHOLDER)
  })

  it('showsOnlyThePlaceholderForAnotherMissingTarget', async () => {
    stubFetch(auditRoutes([makeAuditEvent({ action: 'engine_delete', target: null })]))
    renderApp('/audit')

    expect(await screen.findByText(TARGET_UNAVAILABLE_PLACEHOLDER)).toBeInTheDocument()
    expect(screen.queryByText(TARGET_HIDDEN_EXPLANATION)).not.toBeInTheDocument()
    expect(screen.queryByTitle(TARGET_HIDDEN_EXPLANATION)).not.toBeInTheDocument()
  })

  // Each case types an invalid value: the hint must appear and no request may carry it.
  it.each([
    { fieldLabel: SEARCH_LABEL, typedValue: 'ab', expectedMessage: SEARCH_TOO_SHORT_MESSAGE, parameterName: 'q' },
    { fieldLabel: SEARCH_LABEL, typedValue: 'ssh{Tab}bf', expectedMessage: SEARCH_INVALID_MESSAGE, parameterName: 'q' },
    { fieldLabel: SINCE_LABEL, typedValue: 'yesterday', expectedMessage: en.filters.sinceInvalid, parameterName: 'since' },
    { fieldLabel: ACCOUNT_LABEL, typedValue: 'Alice!', expectedMessage: en.audit.filters.accountInvalid, parameterName: 'account' },
  ])('showsTheHintAndSendsNoRequestFor $parameterName=$typedValue', async ({ fieldLabel, typedValue, expectedMessage, parameterName }) => {
    const fetchMock = stubFetch(auditRoutes([makeAuditEvent()]))
    const user = userEvent.setup()
    renderApp('/audit')
    await screen.findByText('engine_create', { selector: 'td bdi' })

    const filterField = screen.getByLabelText(fieldLabel)
    if (typedValue.includes('{Tab}')) {
      // userEvent would move the focus on {Tab}: paste the control character instead.
      await user.click(filterField)
      await user.paste(typedValue.replace('{Tab}', '\t'))
    } else {
      await user.type(filterField, typedValue)
    }
    await waitForDebounce()

    expect(await screen.findByText(expectedMessage)).toBeInTheDocument()
    const requestsCarryingTheFilter = auditRequestUrls(fetchMock).filter((requestedUrl) => requestedUrl.includes(`${parameterName}=`))
    expect(requestsCarryingTheFilter).toEqual([])
  })

  it('returnsToTheFirstPageWhenAFilterChanges', async () => {
    const fetchMock = stubFetch(
      auditRoutes([makeAuditEvent()], {
        [`GET ${UNFILTERED_AUDIT_URL}`]: { status: 200, body: makePage([makeAuditEvent()], { total: 40 }) },
        [`GET ${SECOND_AUDIT_PAGE_URL}`]: { status: 200, body: makePage([makeAuditEvent({ id: 21, action: 'account_delete' })], { page: 2, total: 40 }) },
        [`GET ${FIRST_PAGE_FILTERED_ON_ACTION_URL}`]: { status: 200, body: makePage([makeAuditEvent({ id: 30, action: 'login_failure', target: null })]) },
      }),
    )
    const user = userEvent.setup()
    renderApp('/audit')
    await screen.findByText('engine_create', { selector: 'td bdi' })

    await user.click(screen.getByRole('button', { name: en.list.next }))
    await screen.findByText('account_delete', { selector: 'td bdi' })
    await user.type(screen.getByLabelText(ACTION_LABEL), 'login_failure')
    await waitForDebounce()

    expect(await screen.findByText('login_failure', { selector: 'td bdi' })).toBeInTheDocument()
    const actionRequests = auditRequestUrls(fetchMock).filter((requestedUrl) => requestedUrl.includes('action='))
    expect(actionRequests).toEqual([FIRST_PAGE_FILTERED_ON_ACTION_URL])
  })

  it('densityToggleHiddenWhenTheListIsEmpty', async () => {
    stubFetch(auditRoutes([]))
    renderApp('/audit')

    await screen.findByText(AUDIT_EMPTY_MESSAGE)
    expect(screen.queryByRole('group', { name: en.list.density.label })).toBeNull()
  })

  it('cardsKeepTheDateAndTheActionPrimaryOnAPhone', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubFetch(auditRoutes([makeAuditEvent()]))
    renderApp('/audit')

    const cardList = await screen.findByRole('list', { name: en.audit.caption })
    const [auditCard] = within(cardList).getAllByRole('listitem')
    // The first block of a card holds the primary columns, the <dl> the secondary ones.
    const primaryBlock = auditCard.firstElementChild as HTMLElement
    expect(primaryBlock).toHaveTextContent('engine_create')
    expect(within(primaryBlock).getByText(en.audit.columns.createdAt)).toHaveClass('sr-only')
    const secondaryBlock = auditCard.querySelector('dl') as HTMLElement
    expect(secondaryBlock).toHaveTextContent('peer-a')
    expect(secondaryBlock).not.toHaveTextContent('engine_create')
  })
})
