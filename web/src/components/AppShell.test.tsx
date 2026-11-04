import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makePage } from '@/test/fixtures'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { findApplicationHeader, prepareEnglishApp } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const DESKTOP_VIEWPORT_WIDTH_IN_PIXELS = 1920
const UNAUTHENTICATED = { status: 401, body: { error: 'unauthenticated' } }
const EMPTY_ALERTS_PAGE = { status: 200, body: makePage([]) }

function sessionFor(accountRole: 'admin' | 'read_only') {
  return { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: accountRole } }
}

// The theme switch names itself after its visible choice (WCAG 2.5.3, label in name).
function themeSwitchName(themeChoiceLabel: string): string {
  return `${en.theme.label}: ${themeChoiceLabel}`
}

// The language switch shows the current language code: its name must contain it too.
const LANGUAGE_SWITCH_NAME = `${en.language.label}: EN`

// The alerts page is the landing page: both of its list requests answer empty
// so the shell is the only thing under test.
function stubSignedInApp(accountRole: 'admin' | 'read_only', extraRoutes: RouteTable = {}) {
  return stubFetch({
    'GET /api/auth/me': sessionFor(accountRole),
    'GET /api/alerts?page=1&per_page=20': EMPTY_ALERTS_PAGE,
    'GET /api/alerts?page=1&per_page=100': EMPTY_ALERTS_PAGE,
    ...extraRoutes,
  })
}

async function findRail(): Promise<HTMLElement> {
  const railNavigation = await screen.findByRole('navigation', { name: en.nav.label })
  return railNavigation.closest('[data-slot=app-rail]')!
}

describe('desktop application shell', () => {
  // The rail only exists on wide screens: pin the width so these cases never
  // depend on the stub's default.
  beforeEach(async () => {
    await prepareEnglishApp()
    setViewportWidth(DESKTOP_VIEWPORT_WIDTH_IN_PIXELS)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    // The theme switch writes the class on <html>, which outlives the render.
    document.documentElement.classList.remove('dark')
  })

  it('railShowsGroupLabelsAndMarksCurrentPage', async () => {
    stubSignedInApp('admin')
    renderApp('/hub')

    const railNavigation = await screen.findByRole('navigation', { name: en.nav.label })

    // Group labels name their link lists without being headings: the page h1 stays the first heading.
    expect(within(railNavigation).queryByRole('heading')).not.toBeInTheDocument()
    expect(within(railNavigation).getByRole('list', { name: en.shell.groups.surveillance })).toBeInTheDocument()
    expect(within(railNavigation).getByRole('list', { name: en.shell.groups.infrastructure })).toBeInTheDocument()
    expect(within(railNavigation).getByRole('list', { name: en.shell.groups.administration })).toBeInTheDocument()
    expect(within(railNavigation).getByRole('link', { name: en.nav.hub })).toHaveAttribute('aria-current', 'page')
    expect(within(railNavigation).getByRole('link', { name: en.nav.alerts })).not.toHaveAttribute('aria-current')
  })

  // A 900 px window used to push the account, language, theme and logout
  // controls below the fold of the rail: only the link list may scroll.
  it('railKeepsItsFooterVisibleAndScrollsOnlyTheLinks', async () => {
    stubSignedInApp('admin')
    renderApp('/alerts')

    const rail = await findRail()
    const railNavigation = within(rail).getByRole('navigation', { name: en.nav.label })
    const railFooter = within(rail).getByRole('button', { name: en.logout }).closest('[data-slot=app-rail-footer]')

    expect(rail.tagName).not.toBe('ASIDE')
    expect(rail).toHaveClass('sticky', 'top-0', 'flex', 'h-screen', 'flex-col', 'overflow-hidden')
    expect(railNavigation).toHaveClass('min-h-0', 'flex-1', 'overflow-y-auto', '[scrollbar-width:thin]')
    expect(railFooter).toHaveClass('shrink-0')
  })

  // The skip link moves focus to <main>: it must accept programmatic focus.
  it('mainContentAcceptsFocusFromTheSkipLink', async () => {
    stubSignedInApp('admin')
    renderApp('/alerts')
    await findRail()

    expect(screen.getByRole('main')).toHaveAttribute('tabindex', '-1')
  })

  it('skipLinkIsTheFirstFocusableElement', async () => {
    stubSignedInApp('admin')
    const user = userEvent.setup()
    renderApp('/alerts')
    await screen.findByRole('navigation', { name: en.nav.label })

    await user.tab()

    expect(screen.getByRole('link', { name: en.app.skipToContent })).toHaveFocus()
  })

  it.each([
    ['admin', en.shell.role.admin],
    ['read_only', en.shell.role.read_only],
  ] as const)('headerShowsTranslatedRole %s', async (accountRole, expectedRoleLabel) => {
    stubSignedInApp(accountRole)
    renderApp('/alerts')

    const applicationHeader = await findApplicationHeader()

    expect(await within(applicationHeader).findByText(expectedRoleLabel)).toBeInTheDocument()
  })

  it('railFooterHoldsAccountLanguageThemeAndLogout', async () => {
    stubSignedInApp('admin')
    renderApp('/alerts')

    const rail = await findRail()

    expect(within(rail).getByText(en.shell.account)).toBeInTheDocument()
    expect(within(rail).getByRole('link', { name: 'alice' })).toHaveAttribute('href', '/account/security')
    expect(within(rail).getByRole('button', { name: LANGUAGE_SWITCH_NAME })).toBeInTheDocument()
    expect(within(rail).getByRole('button', { name: themeSwitchName(en.theme.system) })).toBeInTheDocument()
    expect(within(rail).getByRole('button', { name: en.logout })).toBeInTheDocument()
  })

  // A long account name must end in an ellipsis: truncation only works on a
  // shrinkable inline box, not on the flex link itself.
  it('accountNameTruncatesInsideItsLink', async () => {
    stubSignedInApp('admin')
    renderApp('/alerts')
    const rail = await findRail()

    const accountNameText = within(rail).getByText('alice')

    expect(accountNameText.tagName).toBe('SPAN')
    expect(accountNameText).toHaveClass('min-w-0', 'truncate')
  })

  // Without a name the footer link must not repeat the "Account" label above it.
  it('footerLinkFallsBackToAccountSecurityWithoutAccountName', async () => {
    stubFetch({
      'GET /api/auth/me': { status: 200, body: { status: 'authenticated', account_role: 'admin' } },
      'GET /api/alerts?page=1&per_page=20': EMPTY_ALERTS_PAGE,
      'GET /api/alerts?page=1&per_page=100': EMPTY_ALERTS_PAGE,
    })
    renderApp('/alerts')
    const rail = await findRail()

    expect(within(rail).queryByRole('link', { name: en.shell.account })).not.toBeInTheDocument()
    const accountSecurityLinks = within(rail).getAllByRole('link', { name: en.nav.accountSecurity })
    expect(accountSecurityLinks).toHaveLength(2)
  })

  it('themeSwitchPersistsChoice', async () => {
    stubSignedInApp('admin')
    const user = userEvent.setup()
    renderApp('/alerts')
    const rail = await findRail()

    await user.click(within(rail).getByRole('button', { name: themeSwitchName(en.theme.system) }))
    const systemChoice = await screen.findByRole('menuitemradio', { name: en.theme.system })
    expect(systemChoice).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('menuitemradio', { name: en.theme.light })).toHaveAttribute('aria-checked', 'false')
    await user.click(screen.getByRole('menuitemradio', { name: en.theme.dark }))

    expect(localStorage.getItem('theme-preference')).toBe('dark')
    expect(document.documentElement).toHaveClass('dark')
    await user.click(within(rail).getByRole('button', { name: themeSwitchName(en.theme.dark) }))
    expect(await screen.findByRole('menuitemradio', { name: en.theme.dark })).toHaveAttribute('aria-checked', 'true')
  })

  it('authPagesShowLogoLanguageAndTheme', async () => {
    stubFetch({ 'GET /api/auth/me': UNAUTHENTICATED })
    renderApp('/login')

    await screen.findByRole('heading', { name: en.login.title })

    const logoImage = document.querySelector('img')
    expect(logoImage).toHaveAttribute('src', '/crowdsec-logo.png')
    expect(screen.getByRole('button', { name: LANGUAGE_SWITCH_NAME })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: themeSwitchName(en.theme.system) })).toBeInTheDocument()
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
  })

  it('logoutFailureUsesErrorNotice', async () => {
    stubSignedInApp('admin', { 'POST /api/auth/logout': { status: 500, body: { error: 'internal' } } })
    const user = userEvent.setup()
    renderApp('/alerts')
    const rail = await findRail()

    await user.click(within(rail).getByRole('button', { name: en.logout }))

    const logoutNotice = await screen.findByRole('alert')
    expect(logoutNotice).toHaveAttribute('data-variant', 'critical')
  })
})
