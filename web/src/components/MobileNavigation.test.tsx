import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeHealth, makePage } from '@/test/fixtures'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { prepareEnglishApp } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const PHONE_VIEWPORT_WIDTH_IN_PIXELS = 390
const LAPTOP_VIEWPORT_WIDTH_IN_PIXELS = 1280
const EMPTY_PAGE = { status: 200, body: makePage([]) }

function sessionFor(accountRole: 'admin' | 'read_only') {
  return { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: accountRole } }
}

// The alerts page is the landing page: both of its list requests answer empty
// so the shell is the only thing under test. The hub route lets a test follow a
// link from the Plus sheet to a page living outside the tab bar.
function stubSignedInApp(accountRole: 'admin' | 'read_only', extraRoutes: RouteTable = {}) {
  return stubFetch({
    'GET /api/auth/me': sessionFor(accountRole),
    'GET /api/alerts?page=1&per_page=20': EMPTY_PAGE,
    'GET /api/alerts?page=1&per_page=100': EMPTY_PAGE,
    'GET /api/hub': { status: 200, body: [] },
    'GET /api/health': { status: 200, body: makeHealth() },
    ...extraRoutes,
  })
}

async function findTabBar(): Promise<HTMLElement> {
  return screen.findByRole('navigation', { name: en.shell.mobileNavLabel })
}

async function openPlusSheet(user: ReturnType<typeof userEvent.setup>): Promise<HTMLElement> {
  const tabBar = await findTabBar()
  await user.click(within(tabBar).getByRole('button', { name: en.shell.more }))
  return screen.findByRole('dialog', { name: en.shell.more })
}

describe('mobile navigation', () => {
  beforeEach(async () => {
    await prepareEnglishApp()
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    // The theme menu writes the class on <html>, which outlives the render.
    document.documentElement.classList.remove('dark')
  })

  it('tabBarShowsFourTabsAndPlus', async () => {
    stubSignedInApp('admin')
    renderApp('/alerts')

    const tabBar = await findTabBar()

    const tabLinkNames = within(tabBar)
      .getAllByRole('link')
      .map((tabLink) => tabLink.textContent)
    expect(tabLinkNames).toEqual([en.nav.alerts, en.nav.decisions, en.nav.sync, en.nav.engines])
    expect(within(tabBar).getByRole('button', { name: en.shell.more })).toBeInTheDocument()
    expect(within(tabBar).getByRole('link', { name: en.nav.alerts })).toHaveAttribute('aria-current', 'page')
    expect(screen.queryByRole('navigation', { name: en.nav.label })).not.toBeInTheDocument()
  })

  // Moteurs is admin-only: a read-only account gets Santé in its place rather
  // than a tab that would lead to a page it cannot open.
  it('readOnlyTabBarHasNoEnginesTab', async () => {
    stubSignedInApp('read_only')
    renderApp('/alerts')

    const tabBar = await findTabBar()

    expect(within(tabBar).queryByRole('link', { name: en.nav.engines })).not.toBeInTheDocument()
    const tabLinkNames = within(tabBar)
      .getAllByRole('link')
      .map((tabLink) => tabLink.textContent)
    expect(tabLinkNames).toEqual([en.nav.alerts, en.nav.decisions, en.nav.sync, en.nav.health])
  })

  it('plusSheetListsRemainingPagesGroupedThenControls', async () => {
    stubSignedInApp('admin')
    const user = userEvent.setup()
    renderApp('/alerts')

    const plusSheet = await openPlusSheet(user)

    expect(within(plusSheet).getByRole('heading', { name: en.shell.groups.surveillance })).toBeInTheDocument()
    expect(within(plusSheet).getByRole('heading', { name: en.shell.groups.infrastructure })).toBeInTheDocument()
    expect(within(plusSheet).getByRole('heading', { name: en.shell.groups.administration })).toBeInTheDocument()
    expect(within(plusSheet).getByRole('link', { name: en.nav.hub })).toBeInTheDocument()
    expect(within(plusSheet).getByRole('link', { name: en.nav.health })).toBeInTheDocument()
    expect(within(plusSheet).queryByRole('link', { name: en.nav.alerts })).not.toBeInTheDocument()
    expect(within(plusSheet).queryByRole('link', { name: en.nav.engines })).not.toBeInTheDocument()
    expect(within(plusSheet).getByRole('link', { name: 'alice' })).toHaveAttribute('href', '/account/security')
    expect(within(plusSheet).getByRole('button', { name: en.language.label })).toBeInTheDocument()
    expect(within(plusSheet).getByRole('button', { name: `${en.theme.label}: ${en.theme.system}` })).toBeInTheDocument()
    expect(within(plusSheet).getByRole('button', { name: en.logout })).toBeInTheDocument()
  })

  it('plusSheetClosesOnEscapeAndRestoresFocus', async () => {
    stubSignedInApp('admin')
    const user = userEvent.setup()
    renderApp('/alerts')
    await openPlusSheet(user)

    await user.keyboard('{Escape}')

    expect(screen.queryByRole('dialog', { name: en.shell.more })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.shell.more })).toHaveFocus()
  })

  it('plusSheetClosesAfterNavigating', async () => {
    stubSignedInApp('admin')
    const user = userEvent.setup()
    renderApp('/alerts')
    const plusSheet = await openPlusSheet(user)

    await user.click(within(plusSheet).getByRole('link', { name: en.nav.hub }))

    expect(await screen.findByRole('heading', { name: en.nav.hub, level: 1 })).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: en.shell.more })).not.toBeInTheDocument()
     expect(screen.getByRole('button', { name: en.shell.more })).toHaveFocus()
  })

  // The account link points at the page already shown: no route change happens,
  // so the link itself must close the sheet.
  it('plusSheetClosesWhenAccountLinkTargetsCurrentPage', async () => {
    stubSignedInApp('admin', {
      'GET /api/account/access-rules': { status: 200, body: { rules: [], client_ip: '203.0.113.7', client_country: null } },
    })
    const user = userEvent.setup()
    renderApp('/account/security')
    const plusSheet = await openPlusSheet(user)

    await user.click(within(plusSheet).getByRole('link', { name: 'alice' }))

    expect(screen.queryByRole('dialog', { name: en.shell.more })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.shell.more })).toHaveFocus()
  })

  // The theme menu portals outside the dialog: its radios must still be
  // reachable and usable despite the sheet's focus trap.
  it('themeMenuWorksInsidePlusSheet', async () => {
    stubSignedInApp('admin')
    const user = userEvent.setup()
    renderApp('/alerts')
    const plusSheet = await openPlusSheet(user)

    await user.click(within(plusSheet).getByRole('button', { name: `${en.theme.label}: ${en.theme.system}` }))
    const darkChoice = await screen.findByRole('menuitemradio', { name: en.theme.dark })
    await user.click(darkChoice)

    expect(document.documentElement).toHaveClass('dark')
    expect(within(plusSheet).getByRole('button', { name: `${en.theme.label}: ${en.theme.dark}` })).toBeInTheDocument()
  })

  // Under 768px every target in the sheet must reach 44px (min-h-11).
  it('plusSheetTargetsAreTouchSized', async () => {
    stubSignedInApp('admin')
    const user = userEvent.setup()
    renderApp('/alerts')
    const plusSheet = await openPlusSheet(user)

    expect(within(plusSheet).getByRole('link', { name: en.nav.hub })).toHaveClass('max-md:min-h-11')
    expect(within(plusSheet).getByRole('link', { name: 'alice' })).toHaveClass('max-md:min-h-11')
    expect(within(plusSheet).getByRole('button', { name: en.logout })).toHaveClass('max-md:h-11')
  })

  it('mobileHeaderShowsBrandAndRole', async () => {
    stubSignedInApp('read_only')
    renderApp('/alerts')

    const applicationHeader = await screen.findByRole('banner')

    expect(within(applicationHeader).getByText(en.app.title)).toBeInTheDocument()
    expect(await within(applicationHeader).findByText(en.shell.role.read_only)).toBeInTheDocument()
  })

  it('desktopRendersRailNotTabBar', async () => {
    setViewportWidth(LAPTOP_VIEWPORT_WIDTH_IN_PIXELS)
    stubSignedInApp('admin')
    renderApp('/alerts')

    expect(await screen.findByRole('navigation', { name: en.nav.label })).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: en.shell.mobileNavLabel })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.shell.more })).not.toBeInTheDocument()
  })
})
