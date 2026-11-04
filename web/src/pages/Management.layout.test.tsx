import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeBouncer, makeHealth, makeMachine } from '@/test/fixtures'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { prepareEnglishApp } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const PHONE_VIEWPORT_WIDTH_IN_PIXELS = 390
const FAKE_BOUNCER_KEY = 'fake-bouncer-key-for-layout-tests'

const EXISTING_TOKEN = {
  token_id: 7,
  name: 'ci-reader',
  scope: 'read',
  created_at: '2026-10-01T10:00:00Z',
  expires_at: '2027-01-01T10:00:00Z',
  revoked_at: null,
}

const EXISTING_ACCOUNT = { account_name: 'alice', account_role: 'admin', created_at: '2026-10-01T10:00:00Z', second_factor_enrolled: true, locked: false }

const ACCESS_RULES_WITH_ONE_RULE = {
  status: 200,
  body: { rules: [{ id: 1, kind: 'ip', value: '203.0.113.0/24' }], client_ip: '203.0.113.7', client_country: null },
}

const ACCESS_RULES_EMPTY = { status: 200, body: { rules: [], client_ip: '203.0.113.7', client_country: null } }

const ENGINE_NAMES = { status: 200, body: { items: [{ name: 'local', is_local: true, enabled: true }] } }

function makeAllowlistListing(consoleManaged: boolean) {
  return {
    status: 200,
    body: {
      engine: 'local',
      writable: true,
      truncated: false,
      allowlists: [
        {
          name: 'trusted',
          description: 'trusted description',
          console_managed: consoleManaged,
          created_at: '2026-10-01T10:00:00Z',
          updated_at: '2026-10-02T10:00:00Z',
          entries: [{ value: '192.0.2.10', description: 'office', created_at: '2026-10-01T10:00:00Z', expires_at: null, expired: false }],
        },
      ],
    },
  }
}

// One route table serves every management page, so each it.each case only changes the visited path.
function managementRoutes(extraRoutes: RouteTable = {}): RouteTable {
  return {
    'GET /api/auth/me': ADMIN_SESSION,
    'GET /api/health': {
      status: 200,
      body: makeHealth({
        bouncers: [makeBouncer({ name: 'firewall-one' })],
        machines: [makeMachine({ machine_id: 'remote-agent' }), makeMachine({ machine_id: 'dashboard-self', self: true })],
      }),
    },
    'GET /api/tokens': { status: 200, body: [EXISTING_TOKEN] },
    'GET /api/accounts': { status: 200, body: [EXISTING_ACCOUNT] },
    'GET /api/account/access-rules': ACCESS_RULES_WITH_ONE_RULE,
    'GET /api/engines/names': ENGINE_NAMES,
    'GET /api/engines/local/allowlists': makeAllowlistListing(false),
    ...extraRoutes,
  }
}

const MANAGEMENT_PAGES = [
  { path: '/bouncers', title: en.bouncers.title },
  { path: '/machines', title: en.machines.title },
  { path: '/tokens', title: en.tokens.title },
  { path: '/accounts', title: en.accounts.title },
  { path: '/account/security', title: en.accountSecurity.title },
  { path: '/allowlists', title: en.allowlists.title },
]

const MOBILE_CARD_LISTS = [
  { path: '/bouncers', listName: en.health.bouncersCaption },
  { path: '/machines', listName: en.health.machinesCaption },
  { path: '/tokens', listName: en.tokens.tableCaption },
  { path: '/accounts', listName: en.accounts.tableCaption },
  { path: '/allowlists', listName: en.allowlists.caption.replace('{{name}}', 'trusted') },
]

describe('management pages layout', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it.each(MANAGEMENT_PAGES)('pageHasOneHeadingInPageHeader on $path', async (managementPage) => {
    stubFetch(managementRoutes())
    renderApp(managementPage.path)

    const pageTitle = await screen.findByRole('heading', { level: 1, name: managementPage.title })
    expect(pageTitle.closest('header')).not.toBeNull()
    const pageHeader = pageTitle.closest('header') as HTMLElement

    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(pageTitle).toHaveClass('font-condensed')
    expect(within(pageHeader).getByRole('group', { name: en.list.density.label })).toBeInTheDocument()
  })

  it.each(MOBILE_CARD_LISTS)('mainListsBecomeCardsOnMobile on $path', async (mobileCardList) => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubFetch(managementRoutes())
    renderApp(mobileCardList.path)

    const cardList = await screen.findByRole('list', { name: mobileCardList.listName })

    expect(within(cardList).getAllByRole('listitem').length).toBeGreaterThan(0)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('allowlistEntryCardKeepsMonoValueAndRemoveAction', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubFetch(managementRoutes())
    renderApp('/allowlists')

    const cardList = await screen.findByRole('list', { name: en.allowlists.caption.replace('{{name}}', 'trusted') })
    const [entryCard] = within(cardList).getAllByRole('listitem')

    expect(within(entryCard).getByText('192.0.2.10').closest('.font-mono')).not.toBeNull()
    expect(within(entryCard).getByText('office')).toBeInTheDocument()
    expect(within(entryCard).getByRole('button', { name: en.allowlists.removeEntryLabel.replace('{{value}}', '192.0.2.10') })).toBeInTheDocument()
  })

  it('emptyAccessRulesShowEmptyState', async () => {
    stubFetch(managementRoutes({ 'GET /api/account/access-rules': ACCESS_RULES_EMPTY }))
    renderApp('/account/security')

    const emptyMessage = await screen.findByText(en.accountSecurity.emptyAllowsAll)

    expect(emptyMessage.parentElement).toHaveClass('border-dashed')
  })

  it('onlyTheAccountSecurityHeadingIsAFocusTarget', async () => {
    // Only the account security page moves focus to its title, so only that h1 is programmatically focusable.
    for (const managementPage of MANAGEMENT_PAGES) {
      stubFetch(managementRoutes())
      const { unmount } = renderApp(managementPage.path)
      const pageTitle = await screen.findByRole('heading', { level: 1, name: managementPage.title })
      const isAccountSecurityPage = managementPage.path === '/account/security'

      if (isAccountSecurityPage) {
        expect(pageTitle).toHaveAttribute('tabindex', '-1')
      } else {
        expect(pageTitle).not.toHaveAttribute('tabindex')
      }
      unmount()
      vi.unstubAllGlobals()
    }
  })

  it('focusReturnsToAccountSecurityHeadingAfterDeletingTheLastRule', async () => {
    // The rule list only becomes empty once the DELETE has been served, like the real API.
    let isRuleDeleted = false
    stubFetch(
      managementRoutes({
        'GET /api/account/access-rules': () => (isRuleDeleted ? ACCESS_RULES_EMPTY : ACCESS_RULES_WITH_ONE_RULE),
        'DELETE /api/account/access-rules/1': () => {
          isRuleDeleted = true
          return { status: 204 }
        },
      }),
    )
    const user = userEvent.setup()
    renderApp('/account/security')

    await user.click(await screen.findByRole('button', { name: en.accountSecurity.deleteAria.replace('{{value}}', '203.0.113.0/24') }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(/203\.0\.113\.0\/24/), '203.0.113.0/24')
    await user.click(within(dialog).getByRole('button', { name: en.common.delete }))
    await screen.findByText(en.accountSecurity.emptyAllowsAll)

    await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: en.accountSecurity.title })).toHaveFocus())
  })

  it('selfDeleteButtonIsOutlineDestructive', async () => {
    stubFetch(managementRoutes())
    renderApp('/machines')

    const selfDeleteButton = await screen.findByRole('button', { name: en.machines.deleteAria.replace('{{name}}', 'dashboard-self') })
    const otherDeleteButton = screen.getByRole('button', { name: en.machines.deleteAria.replace('{{name}}', 'remote-agent') })

    expect(selfDeleteButton).toHaveAttribute('data-variant', 'destructiveOutline')
    expect(selfDeleteButton).toBeDisabled()
    expect(otherDeleteButton).toHaveAttribute('data-variant', 'destructiveOutline')
  })

  it('secretRevealIsMonoWithAaContrast', async () => {
    stubFetch(managementRoutes({ 'POST /api/bouncers': { status: 200, body: { name: 'new-one', key: FAKE_BOUNCER_KEY } } }))
    const user = userEvent.setup()
    renderApp('/bouncers')

    await user.click(await screen.findByRole('button', { name: en.bouncers.add }))
    const dialog = await screen.findByRole('dialog', { name: en.bouncers.addTitle })
    await user.type(within(dialog).getByLabelText(en.bouncers.nameLabel), 'new-one')
    await user.click(within(dialog).getByRole('button', { name: en.secret.create }))
    const revealedSecret = await within(dialog).findByText(FAKE_BOUNCER_KEY)

    expect(revealedSecret.tagName).toBe('CODE')
    expect(revealedSecret).toHaveClass('font-mono', 'bg-secondary', 'text-foreground')
    expect(revealedSecret).not.toHaveClass('bg-muted')
  })

  it('consoleManagedBadgeIsInfo', async () => {
    stubFetch(managementRoutes({ 'GET /api/engines/local/allowlists': makeAllowlistListing(true) }))
    renderApp('/allowlists')

    expect(await screen.findByText(en.allowlists.consoleManaged)).toHaveAttribute('data-variant', 'info')
  })
})
