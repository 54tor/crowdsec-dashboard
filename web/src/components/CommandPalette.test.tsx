import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { makeAlert, makeDecision, makePage, MALICIOUS_SCENARIO } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { findApplicationHeader, INJECTED_IMAGE_SELECTOR, prepareEnglishApp, requestedUrls, SESSION_OK, waitForDebounce } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

// Exact en.json values of the palette keys, quoted so a missing key fails the test.
const OPEN_PALETTE_LABEL = 'Search everywhere'
const PALETTE_INPUT_LABEL = 'Search pages, engines, alerts and decisions'
const TYPE_MORE_MESSAGE = 'Type at least 3 characters to search alerts and decisions'
const ALERTS_GROUP_HEADING = 'Alerts'
const DECISIONS_GROUP_HEADING = 'Decisions'
// Existing en.json values used by the pages the palette opens.
const FILTER_SEARCH_LABEL = 'Search'
const BAN_BUTTON_LABEL = 'Ban IP'
const MOBILE_VIEWPORT_WIDTH_IN_PIXELS = 390

const READ_ONLY_SESSION = { status: 200, body: { status: 'ok', account_name: 'bob', account_role: 'read_only' } }
const ENGINE_NAMES_BODY = { items: [{ name: 'local', is_local: true, enabled: true }, { name: 'peer-a', is_local: false, enabled: true }] }

const PALETTE_ALERTS_URL = '/api/alerts?page=1&per_page=5&q=ssh-bf'
const PALETTE_DECISIONS_URL = '/api/decisions?page=1&per_page=5&q=ssh-bf'

// jsdom has neither ResizeObserver nor scrollIntoView; cmdk uses both to size the list and
// keep the active option visible. Inert stand-ins are enough: layout is not under test.
class InertResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function installLayoutStubs() {
  vi.stubGlobal('ResizeObserver', InertResizeObserver)
  Element.prototype.scrollIntoView = () => {}
}

function shellRoutes(session = SESSION_OK) {
  return {
    'GET /api/auth/me': session,
    'GET /api/engines/names': { status: 200, body: ENGINE_NAMES_BODY },
    'GET /api/alerts?page=1&per_page=20': { status: 200, body: makePage([makeAlert()]) },
    'GET /api/alerts?page=1&per_page=100': { status: 200, body: makePage([makeAlert()]) },
    'GET /api/decisions?page=1&per_page=20': { status: 200, body: makePage([makeDecision()]) },
  }
}

function paletteRecordRoutes() {
  return {
    [`GET ${PALETTE_ALERTS_URL}`]: { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/ssh-bf-result' })], { per_page: 5 }) },
    [`GET ${PALETTE_DECISIONS_URL}`]: { status: 200, body: makePage([makeDecision({ value: '198.51.100.20' })], { per_page: 5 }) },
  }
}

async function renderAlertsPage(initialPath = '/alerts') {
  const renderResult = renderApp(initialPath)
  await screen.findByText('crowdsecurity/ssh-bf', { selector: 'td bdi' })
  return renderResult
}

async function openPaletteWithShortcut(user: ReturnType<typeof userEvent.setup>) {
  await user.keyboard('{Control>}k{/Control}')
  return screen.findByRole('dialog', { name: OPEN_PALETTE_LABEL })
}

function paletteInput(): HTMLElement {
  return screen.getByRole('combobox', { name: PALETTE_INPUT_LABEL })
}

function selectedOptionText(): string | null | undefined {
  return screen.getAllByRole('option').find((optionElement) => optionElement.getAttribute('aria-selected') === 'true')?.textContent
}

describe('command palette', () => {
  beforeEach(async () => {
    installLayoutStubs()
    await prepareEnglishApp()
  })
  afterEach(() => vi.unstubAllGlobals())

  it('ctrlKOpensThePaletteFromInsideATextField', async () => {
    stubFetch(shellRoutes())
    const user = userEvent.setup()
    await renderAlertsPage()
    await user.click(screen.getByLabelText(FILTER_SEARCH_LABEL))

    await openPaletteWithShortcut(user)

    expect(paletteInput()).toHaveFocus()
    // The shortcut is swallowed: the letter k never reaches the filter field.
    expect(screen.getByLabelText(FILTER_SEARCH_LABEL)).toHaveValue('')
  })

  it('metaKOpensThePalette', async () => {
    stubFetch(shellRoutes())
    const user = userEvent.setup()
    await renderAlertsPage()

    await user.keyboard('{Meta>}k{/Meta}')

    expect(await screen.findByRole('dialog', { name: OPEN_PALETTE_LABEL })).toBeInTheDocument()
    expect(paletteInput()).toHaveFocus()
  })

  it('headerButtonOpensThePaletteAndIsShownOnMobile', async () => {
    setViewportWidth(MOBILE_VIEWPORT_WIDTH_IN_PIXELS)
    stubFetch(shellRoutes())
    const user = userEvent.setup()
    renderApp('/alerts')
    const applicationHeader = await findApplicationHeader()
    const openButton = await within(applicationHeader).findByRole('button', { name: OPEN_PALETTE_LABEL })

    expect(openButton).toHaveAttribute('aria-keyshortcuts', 'Control+K Meta+K')
    await user.click(openButton)

    expect(await screen.findByRole('dialog', { name: OPEN_PALETTE_LABEL })).toBeInTheDocument()
  })

  it('ctrlKDoesNothingWhileAnotherDialogIsOpen', async () => {
    stubFetch(shellRoutes())
    const user = userEvent.setup()
    renderApp('/decisions')
    await user.click(await screen.findByRole('button', { name: BAN_BUTTON_LABEL }))
    const banDialog = await screen.findByRole('dialog')

    await user.keyboard('{Control>}k{/Control}')

    expect(screen.getAllByRole('dialog')).toEqual([banDialog])
    expect(screen.queryByRole('combobox', { name: PALETTE_INPUT_LABEL })).not.toBeInTheDocument()
  })

  it('escapeClosesAndReturnsFocusToThePreviouslyFocusedElement', async () => {
    stubFetch(shellRoutes())
    const user = userEvent.setup()
    await renderAlertsPage()
    const filterSearchField = screen.getByLabelText(FILTER_SEARCH_LABEL)
    await user.click(filterSearchField)
    await openPaletteWithShortcut(user)

    await user.keyboard('{Escape}')

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(filterSearchField).toHaveFocus()
  })

  it('arrowKeysMoveTheActiveOptionAndEnterActivatesIt', async () => {
    stubFetch(shellRoutes())
    const user = userEvent.setup()
    const { visitedLocations } = await renderAlertsPage()
    await openPaletteWithShortcut(user)

    // 'e' matches several pages; Alerts comes first in the navigation order, Decisions second.
    await user.type(paletteInput(), 'e')
    await waitFor(() => expect(selectedOptionText()).toBe('Alerts'))
    await user.keyboard('{ArrowDown}')
    expect(selectedOptionText()).toBe('Decisions')
    expect(paletteInput()).toHaveAttribute('aria-activedescendant')
    await user.keyboard('{Enter}')

    await waitFor(() => expect(visitedLocations.at(-1)).toBe('/decisions'))
    expect(screen.queryByRole('dialog', { name: OPEN_PALETTE_LABEL })).not.toBeInTheDocument()
  })

  it('readOnlyPaletteListsNoAdminPage', async () => {
    stubFetch(shellRoutes(READ_ONLY_SESSION))
    const user = userEvent.setup()
    await renderAlertsPage()
    await openPaletteWithShortcut(user)

    // Each admin label is typed in full, so the per-category limit of 5 cannot hide a leak.
    for (const adminPageLabel of ['Engines', 'Config', 'Accounts', 'Export / Import', 'Audit log']) {
      await user.clear(paletteInput())
      await user.type(paletteInput(), adminPageLabel)
      expect(screen.queryByRole('option', { name: adminPageLabel })).not.toBeInTheDocument()
    }
    // Control: a page open to every role is still offered.
    await user.clear(paletteInput())
    await user.type(paletteInput(), 'Account security')
    expect(await screen.findByRole('option', { name: 'Account security' })).toBeInTheDocument()
  })

  it('adminPaletteListsTheAdminPages', async () => {
    stubFetch(shellRoutes())
    const user = userEvent.setup()
    await renderAlertsPage()
    await openPaletteWithShortcut(user)

    await user.type(paletteInput(), 'Audit log')

    expect(await screen.findByRole('option', { name: 'Audit log' })).toBeInTheDocument()
  })

  it('engineResultOpensAlertsFilteredOnThatEngine', async () => {
    const fetchMock = stubFetch({
      ...shellRoutes(),
      'GET /api/engines/names': { status: 200, body: { items: [{ name: 'peer-a', is_local: false, enabled: true }] } },
      'GET /api/alerts?page=1&per_page=20&engine=peer-a': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/peer-row' })]) },
    })
    const user = userEvent.setup()
    const { visitedLocations, visitedPaths } = await renderAlertsPage()
    await openPaletteWithShortcut(user)

    await user.type(paletteInput(), 'peer')
    await waitFor(() => expect(selectedOptionText()).toBe('peer-a'))
    await user.keyboard('{Enter}')

    await waitFor(() => expect(visitedLocations.at(-1)).toBe('/alerts?engine=peer-a'))
    expect(await screen.findByText('crowdsecurity/peer-row')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain('/api/alerts?page=1&per_page=20&engine=peer-a')
    expect(visitedPaths).not.toContain('/engines')
  })

  it('alertResultsComeFromTheListRouteWithPerPageFive', async () => {
    const fetchMock = stubFetch({ ...shellRoutes(), ...paletteRecordRoutes() })
    const user = userEvent.setup()
    await renderAlertsPage()
    await openPaletteWithShortcut(user)

    await user.type(paletteInput(), 'ss')
    await waitForDebounce()
    expect(screen.getByText(TYPE_MORE_MESSAGE)).toBeInTheDocument()
    expect(requestedUrls(fetchMock).some((requestedUrl) => requestedUrl.includes('per_page=5'))).toBe(false)

    await user.type(paletteInput(), 'h-bf')
    await waitForDebounce()

    expect(await screen.findByRole('group', { name: ALERTS_GROUP_HEADING })).toBeInTheDocument()
    expect(await screen.findByRole('option', { name: 'crowdsecurity/ssh-bf-result 203.0.113.7' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: DECISIONS_GROUP_HEADING })).toBeInTheDocument()
    const paletteRequestUrls = requestedUrls(fetchMock).filter((requestedUrl) => requestedUrl.includes('per_page=5'))
    expect(paletteRequestUrls).toContain(PALETTE_ALERTS_URL)
    expect(paletteRequestUrls).toContain(PALETTE_DECISIONS_URL)
    // Every palette request carries the whole debounced term, never a prefix.
    expect(paletteRequestUrls.every((requestedUrl) => requestedUrl.endsWith('&q=ssh-bf'))).toBe(true)
  })

  it('hostileResultTextIsRenderedAsText', async () => {
    stubFetch({
      ...shellRoutes(),
      [`GET ${PALETTE_ALERTS_URL}`]: { status: 200, body: makePage([makeAlert({ scenario: MALICIOUS_SCENARIO })], { per_page: 5 }) },
      [`GET ${PALETTE_DECISIONS_URL}`]: { status: 200, body: makePage([]) },
    })
    const user = userEvent.setup()
    await renderAlertsPage()
    const paletteDialog = await openPaletteWithShortcut(user)

    await user.type(paletteInput(), 'ssh-bf')
    await waitForDebounce()

    const hostileText = await within(paletteDialog).findByText(MALICIOUS_SCENARIO)
    expect(hostileText.tagName).toBe('BDI')
    expect(paletteDialog.querySelector(INJECTED_IMAGE_SELECTOR)).toBeNull()
    expect(paletteDialog.querySelector('[role="option"] a')).toBeNull()
  })

  it('paletteNavigationWhileOnAlertsAppliesTheNewSearch', async () => {
    const fetchMock = stubFetch({
      ...shellRoutes(),
      ...paletteRecordRoutes(),
      'GET /api/alerts?page=1&per_page=20&q=ssh-bf': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/searched-row' })]) },
    })
    const user = userEvent.setup()
    const { visitedLocations } = await renderAlertsPage()
    await openPaletteWithShortcut(user)

    await user.type(paletteInput(), ' ssh-bf ')
    await waitForDebounce()
    await user.click(await screen.findByRole('option', { name: 'crowdsecurity/ssh-bf-result 203.0.113.7' }))

    await waitFor(() => expect(visitedLocations.at(-1)).toBe('/alerts?q=ssh-bf'))
    expect(screen.getByLabelText(FILTER_SEARCH_LABEL)).toHaveValue('ssh-bf')
    await waitForDebounce()
    expect(await screen.findByText('crowdsecurity/searched-row')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain('/api/alerts?page=1&per_page=20&q=ssh-bf')
  })

  it('decisionResultOpensDecisionsWithTheTypedTermPrefilled', async () => {
    const fetchMock = stubFetch({
      ...shellRoutes(),
      ...paletteRecordRoutes(),
      'GET /api/alerts?page=1&per_page=20&q=abc': { status: 200, body: makePage([makeAlert({ scenario: 'crowdsecurity/abc-row' })]) },
      'GET /api/alerts?page=1&per_page=100&q=abc': { status: 200, body: makePage([]) },
      'GET /api/decisions?page=1&per_page=20&q=ssh-bf': { status: 200, body: makePage([makeDecision({ value: '198.51.100.21' })]) },
    })
    const user = userEvent.setup()
    const { visitedLocations } = renderApp('/alerts?q=abc')
    expect(await screen.findByText('crowdsecurity/abc-row')).toBeInTheDocument()
    await openPaletteWithShortcut(user)

    await user.type(paletteInput(), 'ssh-bf')
    await waitForDebounce()
    await user.click(await screen.findByRole('option', { name: '198.51.100.20 ban crowdsecurity/ssh-bf' }))

    await waitFor(() => expect(visitedLocations.at(-1)).toBe('/decisions?q=ssh-bf'))
    expect(await screen.findByText('198.51.100.21', { selector: 'td bdi' })).toBeInTheDocument()
    expect(screen.getByLabelText(FILTER_SEARCH_LABEL)).toHaveValue('ssh-bf')
    expect(requestedUrls(fetchMock)).toContain('/api/decisions?page=1&per_page=20&q=ssh-bf')
  })
})
