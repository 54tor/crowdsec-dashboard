import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makePage } from '@/test/fixtures'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { prepareEnglishApp } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const UNAUTHENTICATED = { status: 401, body: { error: 'unauthenticated' } }
const EMPTY_ALERTS_PAGE = { status: 200, body: makePage([]) }

function sessionFor(accountRole: 'admin' | 'read_only') {
  return { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: accountRole } }
}

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
  return railNavigation.closest('aside')!
}

describe('desktop application shell', () => {
  beforeEach(async () => {
    await prepareEnglishApp()
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

    expect(within(railNavigation).getByRole('heading', { name: en.shell.groups.surveillance })).toBeInTheDocument()
    expect(within(railNavigation).getByRole('heading', { name: en.shell.groups.infrastructure })).toBeInTheDocument()
    expect(within(railNavigation).getByRole('heading', { name: en.shell.groups.administration })).toBeInTheDocument()
    expect(within(railNavigation).getByRole('link', { name: en.nav.hub })).toHaveAttribute('aria-current', 'page')
    expect(within(railNavigation).getByRole('link', { name: en.nav.alerts })).not.toHaveAttribute('aria-current')
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

    const applicationHeader = await screen.findByRole('banner')

    expect(await within(applicationHeader).findByText(expectedRoleLabel)).toBeInTheDocument()
  })

  it('railFooterHoldsAccountLanguageThemeAndLogout', async () => {
    stubSignedInApp('admin')
    renderApp('/alerts')

    const rail = await findRail()

    expect(within(rail).getByText(en.shell.account)).toBeInTheDocument()
    expect(within(rail).getByRole('link', { name: 'alice' })).toHaveAttribute('href', '/account/security')
    expect(within(rail).getByRole('button', { name: en.language.label })).toBeInTheDocument()
    expect(within(rail).getByRole('button', { name: en.theme.label })).toBeInTheDocument()
    expect(within(rail).getByRole('button', { name: en.logout })).toBeInTheDocument()
  })

  it('themeSwitchPersistsChoice', async () => {
    stubSignedInApp('admin')
    const user = userEvent.setup()
    renderApp('/alerts')
    const rail = await findRail()

    await user.click(within(rail).getByRole('button', { name: en.theme.label }))
    const systemChoice = await screen.findByRole('menuitemradio', { name: en.theme.system })
    expect(systemChoice).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('menuitemradio', { name: en.theme.light })).toHaveAttribute('aria-checked', 'false')
    await user.click(screen.getByRole('menuitemradio', { name: en.theme.dark }))

    expect(localStorage.getItem('theme-preference')).toBe('dark')
    expect(document.documentElement).toHaveClass('dark')
    await user.click(within(rail).getByRole('button', { name: en.theme.label }))
    expect(await screen.findByRole('menuitemradio', { name: en.theme.dark })).toHaveAttribute('aria-checked', 'true')
  })

  it('authPagesShowLogoLanguageAndTheme', async () => {
    stubFetch({ 'GET /api/auth/me': UNAUTHENTICATED })
    renderApp('/login')

    await screen.findByRole('heading', { name: en.login.title })

    const logoImage = document.querySelector('img')
    expect(logoImage).toHaveAttribute('src', '/crowdsec-logo.png')
    expect(screen.getByRole('button', { name: en.language.label })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.theme.label })).toBeInTheDocument()
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
