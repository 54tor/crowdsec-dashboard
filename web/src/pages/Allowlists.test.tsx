import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { stubFetch, type RouteTable, type StubbedResponse } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }

const ENGINE_NAMES = {
  status: 200,
  body: {
    items: [
      { name: 'local', is_local: true, enabled: true },
      { name: 'remote-one', is_local: false, enabled: true },
    ],
  },
}

const LOCAL_LISTING_URL = '/api/engines/local/allowlists'
const REMOTE_LISTING_URL = '/api/engines/remote-one/allowlists'
const TRUSTED_ENTRIES_URL = '/api/engines/local/allowlists/trusted/entries'

interface EntryOverrides {
  value: string
  description?: string
  expires_at?: string | null
  expired?: boolean
}

function makeEntry(overrides: EntryOverrides) {
  return { description: '', created_at: '2026-10-01T10:00:00Z', expires_at: null, expired: false, ...overrides }
}

function makeAllowlist(name: string, entries: ReturnType<typeof makeEntry>[], consoleManaged = false) {
  return {
    name,
    description: `${name} description`,
    console_managed: consoleManaged,
    created_at: '2026-10-01T10:00:00Z',
    updated_at: '2026-10-02T10:00:00Z',
    entries,
  }
}

function makeListing(engine: string, allowlists: ReturnType<typeof makeAllowlist>[], overrides: { writable?: boolean; truncated?: boolean } = {}) {
  return { status: 200, body: { engine, writable: true, truncated: false, allowlists, ...overrides } }
}

const TRUSTED_ALLOWLIST = makeAllowlist('trusted', [makeEntry({ value: '192.0.2.10', description: 'office' })])

function allowlistRoutes(extraRoutes: RouteTable = {}): RouteTable {
  return {
    'GET /api/auth/me': ADMIN_SESSION,
    'GET /api/engines/names': ENGINE_NAMES,
    [`GET ${LOCAL_LISTING_URL}`]: makeListing('local', [TRUSTED_ALLOWLIST]),
    ...extraRoutes,
  }
}

function lastJsonBody(fetchMock: { mock: { calls: unknown[][] } }, method: string, url: string): Record<string, unknown> {
  const matchingRequests = requestsTo(fetchMock, method, url)
  return JSON.parse(String(matchingRequests[matchingRequests.length - 1].body))
}

async function openAddEntryDialog(user: ReturnType<typeof userEvent.setup>, allowlistName: string) {
  await user.click(await screen.findByRole('button', { name: en.allowlists.addEntryLabel.replace('{{name}}', allowlistName) }))
  return screen.findByRole('dialog')
}

function mutationResponse(status: number, refreshed: boolean): StubbedResponse {
  return { status, body: { engine: 'local', writable: true, truncated: false, allowlists: refreshed ? [TRUSTED_ALLOWLIST] : [], refreshed } }
}

function collectKeyPaths(node: unknown, prefix = ''): string[] {
  if (node === null || typeof node !== 'object') {
    return [prefix]
  }
  return Object.entries(node).flatMap(([childKey, childNode]) => collectKeyPaths(childNode, prefix ? `${prefix}.${childKey}` : childKey))
}

const CONFIG_LINK_TEXT = /<configLink>(.*)<\/configLink>/.exec(en.allowlists.configNote)![1]

const ALLOWLIST_ERROR_CODES = [
  'allowlist_not_found',
  'allowlist_exists',
  'allowlist_entry_exists',
  'allowlist_entry_not_found',
  'allowlist_console_managed',
  'allowlist_engine_readonly',
  'allowlist_prefix_too_wide',
  'invalid_allowlist',
  'allowlist_write_failed',
  'database_unavailable',
  'engine_not_found',
  'engine_unreachable',
]

describe('allowlists page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('liste les allowlists du moteur choisi', async () => {
    const remoteAllowlist = makeAllowlist('partners', [makeEntry({ value: '198.51.100.0/24' })])
    const fetchMock = stubFetch(allowlistRoutes({ [`GET ${REMOTE_LISTING_URL}`]: makeListing('remote-one', [remoteAllowlist]) }))
    const user = userEvent.setup()
    renderApp('/allowlists')

    expect(await screen.findByRole('heading', { name: en.nav.allowlists })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'trusted' })).toBeInTheDocument()
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.allowlists.create })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: CONFIG_LINK_TEXT })).toHaveAttribute('href', '/config')

    await user.selectOptions(await screen.findByLabelText(en.allowlists.engine), 'remote-one')

    expect(await screen.findByRole('heading', { name: 'partners' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'trusted' })).not.toBeInTheDocument()
    expect(requestsTo(fetchMock, 'GET', REMOTE_LISTING_URL)).toHaveLength(1)
  })

  it('un compte read_only voit les allowlists du moteur local', async () => {
    const fetchMock = stubFetch(allowlistRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION }))
    renderApp('/allowlists')

    expect(await screen.findByRole('heading', { name: 'trusted' })).toBeInTheDocument()
    expect(await screen.findByRole('option', { name: 'remote-one' })).toBeInTheDocument()
    expect(requestsTo(fetchMock, 'GET', '/api/engines/names').length).toBeGreaterThan(0)
    expect(requestsTo(fetchMock, 'GET', '/api/engines')).toHaveLength(0)
    expect(screen.getByRole('link', { name: en.nav.allowlists })).toBeInTheDocument()
  })

  it('masque les actions pour un compte read_only', async () => {
    stubFetch(allowlistRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION }))
    renderApp('/allowlists')

    await screen.findByRole('heading', { name: 'trusted' })
    expect(screen.queryByRole('button', { name: en.allowlists.create })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.allowlists.addEntryLabel.replace('{{name}}', 'trusted') })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.allowlists.deleteLabel.replace('{{name}}', 'trusted') })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.allowlists.removeEntryLabel.replace('{{value}}', '192.0.2.10') })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: CONFIG_LINK_TEXT })).not.toBeInTheDocument()
  })

  it('affiche le bandeau lecture seule pour un moteur distant', async () => {
    stubFetch(allowlistRoutes({ [`GET ${LOCAL_LISTING_URL}`]: makeListing('local', [TRUSTED_ALLOWLIST], { writable: false }) }))
    renderApp('/allowlists')

    expect(await screen.findByText(en.allowlists.readOnly)).toBeInTheDocument()
    await screen.findByRole('heading', { name: 'trusted' })
    expect(screen.queryByRole('button', { name: en.allowlists.create })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.allowlists.addEntryLabel.replace('{{name}}', 'trusted') })).not.toBeInTheDocument()
  })

  it('affiche le bandeau de troncature', async () => {
    stubFetch(allowlistRoutes({ [`GET ${LOCAL_LISTING_URL}`]: makeListing('local', [TRUSTED_ALLOWLIST], { truncated: true }) }))
    renderApp('/allowlists')

    expect(await screen.findByText(en.allowlists.truncated)).toBeInTheDocument()
  })

  it("exige la ressaisie pour une plage plus large que /24 et prévient de l'expiration des décisions", async () => {
    const fetchMock = stubFetch(allowlistRoutes({ [`POST ${TRUSTED_ENTRIES_URL}`]: mutationResponse(201, true) }))
    const user = userEvent.setup()
    renderApp('/allowlists')

    const narrowDialog = await openAddEntryDialog(user, 'trusted')
    await user.type(within(narrowDialog).getByLabelText(en.allowlists.value), '10.0.5.0/24')
    expect(within(narrowDialog).queryByText(en.allowlists.wideRangeWarning)).not.toBeInTheDocument()
    await user.click(within(narrowDialog).getByRole('button', { name: en.dialog.cancel }))

    const wideDialog = await openAddEntryDialog(user, 'trusted')
    await user.type(within(wideDialog).getByLabelText(en.allowlists.value), '10.0.5.7/16')
    expect(within(wideDialog).getByText(en.allowlists.wideRangeWarning)).toBeInTheDocument()
    const submitButton = within(wideDialog).getByRole('button', { name: en.allowlists.entrySubmit })
    expect(submitButton).toBeDisabled()

    const confirmField = within(wideDialog).getByLabelText(en.allowlists.wideRangeConfirm.replace('{{value}}', '10.0.0.0/16'))
    await user.type(confirmField, '10.0.5.7/16')
    expect(submitButton).toBeDisabled()
    expect(within(wideDialog).getByText(en.allowlists.wideRangeMismatch)).toBeInTheDocument()
    await user.clear(confirmField)
    await user.type(confirmField, ' 10.0.0.0/16 ')
    expect(within(wideDialog).queryByText(en.allowlists.wideRangeMismatch)).not.toBeInTheDocument()
    await user.click(within(wideDialog).getByRole('button', { name: '7d' }))
    await user.click(submitButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', TRUSTED_ENTRIES_URL)).toHaveLength(1))
    expect(lastJsonBody(fetchMock, 'POST', TRUSTED_ENTRIES_URL)).toEqual({ value: '10.0.5.7/16', expiration: '7d', confirm: '10.0.0.0/16' })
  })

  it('traduit allowlist_prefix_too_wide et allowlist_console_managed', async () => {
    // The listing is stale: it still says console_managed:false while the engine now refuses with 409.
    stubFetch(
      allowlistRoutes({
        [`POST ${TRUSTED_ENTRIES_URL}`]: { status: 400, body: { error: 'allowlist_prefix_too_wide' } },
        [`DELETE ${TRUSTED_ENTRIES_URL}`]: { status: 409, body: { error: 'allowlist_console_managed' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/allowlists')

    const entryDialog = await openAddEntryDialog(user, 'trusted')
    await user.type(within(entryDialog).getByLabelText(en.allowlists.value), '10.0.0.0/4')
    await user.type(within(entryDialog).getByLabelText(en.allowlists.wideRangeConfirm.replace('{{value}}', '0.0.0.0/4')), '0.0.0.0/4')
    await user.click(within(entryDialog).getByRole('button', { name: en.allowlists.entrySubmit }))
    expect(await within(entryDialog).findByText(en.errors.allowlist_prefix_too_wide)).toBeInTheDocument()
    await user.click(within(entryDialog).getByRole('button', { name: en.dialog.cancel }))

    await user.click(screen.getByRole('button', { name: en.allowlists.removeEntryLabel.replace('{{value}}', '192.0.2.10') }))
    const removeDialog = await screen.findByRole('dialog')
    await user.type(within(removeDialog).getByLabelText(en.confirmDelete.label.replace('{{target}}', '192.0.2.10')), '192.0.2.10')
    await user.click(within(removeDialog).getByRole('button', { name: en.allowlists.removeEntry }))
    expect(await within(removeDialog).findByText(en.errors.allowlist_console_managed)).toBeInTheDocument()
  })

  it('désactive les actions d\'une allowlist gérée par la console', async () => {
    const consoleAllowlist = makeAllowlist('console-list', [makeEntry({ value: '203.0.113.9' })], true)
    stubFetch(allowlistRoutes({ [`GET ${LOCAL_LISTING_URL}`]: makeListing('local', [TRUSTED_ALLOWLIST, consoleAllowlist]) }))
    renderApp('/allowlists')

    expect(await screen.findByText(en.allowlists.consoleManaged)).toBeInTheDocument()
    const consoleActions = [
      screen.getByRole('button', { name: en.allowlists.addEntryLabel.replace('{{name}}', 'console-list') }),
      screen.getByRole('button', { name: en.allowlists.deleteLabel.replace('{{name}}', 'console-list') }),
      screen.getByRole('button', { name: en.allowlists.removeEntryLabel.replace('{{value}}', '203.0.113.9') }),
    ]
    for (const consoleAction of consoleActions) {
      expect(consoleAction).toBeDisabled()
      expect(consoleAction).toHaveAttribute('title', en.errors.allowlist_console_managed)
    }
    expect(screen.getByRole('button', { name: en.allowlists.addEntryLabel.replace('{{name}}', 'trusted') })).toBeEnabled()
  })

  it('réutilise la liste renvoyée par une écriture sans relire le moteur', async () => {
    const updatedAllowlist = makeAllowlist('trusted', [makeEntry({ value: '192.0.2.10' }), makeEntry({ value: '192.0.2.55' })])
    const fetchMock = stubFetch(
      allowlistRoutes({
        [`POST ${TRUSTED_ENTRIES_URL}`]: { status: 201, body: { engine: 'local', writable: true, truncated: false, allowlists: [updatedAllowlist], refreshed: true } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/allowlists')

    const entryDialog = await openAddEntryDialog(user, 'trusted')
    const listingReadsBeforeWrite = requestsTo(fetchMock, 'GET', LOCAL_LISTING_URL).length
    await user.type(within(entryDialog).getByLabelText(en.allowlists.value), '192.0.2.55')
    await user.click(within(entryDialog).getByRole('button', { name: en.allowlists.entrySubmit }))

    expect(await screen.findByText('192.0.2.55')).toBeInTheDocument()
    expect(requestsTo(fetchMock, 'GET', LOCAL_LISTING_URL)).toHaveLength(listingReadsBeforeWrite)
    expect(screen.queryByText(en.allowlists.refreshFailed)).not.toBeInTheDocument()
  })

  it('refuse un commentaire qui commence par un tiret ou contient un saut de ligne', async () => {
    const fetchMock = stubFetch(allowlistRoutes())
    const user = userEvent.setup()
    renderApp('/allowlists')

    const entryDialog = await openAddEntryDialog(user, 'trusted')
    await user.type(within(entryDialog).getByLabelText(en.allowlists.value), '192.0.2.60')
    const commentField = within(entryDialog).getByLabelText(en.allowlists.entryComment)
    await user.type(commentField, '-flag')

    expect(within(entryDialog).getByText(en.allowlists.textLeadingDash)).toBeInTheDocument()
    expect(within(entryDialog).getByRole('button', { name: en.allowlists.entrySubmit })).toBeDisabled()
    expect(requestsTo(fetchMock, 'POST', TRUSTED_ENTRIES_URL)).toHaveLength(0)
  })

  it('marque les entrées expirées', async () => {
    const mixedAllowlist = makeAllowlist('mixed', [
      makeEntry({ value: '192.0.2.20', expires_at: '2026-01-01T00:00:00Z', expired: true }),
      makeEntry({ value: '192.0.2.21' }),
    ])
    stubFetch(allowlistRoutes({ [`GET ${LOCAL_LISTING_URL}`]: makeListing('local', [mixedAllowlist]) }))
    renderApp('/allowlists')

    const expiredRow = (await screen.findByText('192.0.2.20')).closest('tr')!
    expect(within(expiredRow).getByText(en.allowlists.expired)).toBeInTheDocument()
    const permanentRow = screen.getByText('192.0.2.21').closest('tr')!
    expect(within(permanentRow).getByText(en.allowlists.noExpiry)).toBeInTheDocument()
    expect(within(permanentRow).queryByText(en.allowlists.expired)).not.toBeInTheDocument()
  })

  it('pagine 800 entrées', async () => {
    const manyEntries = Array.from({ length: 800 }, (_, entryIndex) => makeEntry({ value: `10.${Math.floor(entryIndex / 256)}.${entryIndex % 256}.1` }))
    stubFetch(allowlistRoutes({ [`GET ${LOCAL_LISTING_URL}`]: makeListing('local', [makeAllowlist('big', manyEntries)]) }))
    const user = userEvent.setup()
    renderApp('/allowlists')

    expect(await screen.findByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getAllByRole('row')).toHaveLength(51)
    expect(screen.getByText('Page 1 of 16')).toBeInTheDocument()
    expect(screen.queryByText('10.0.50.1')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: en.list.next }))

    expect(await screen.findByText('10.0.50.1')).toBeInTheDocument()
    expect(screen.queryByText('10.0.0.1')).not.toBeInTheDocument()
    expect(screen.getByText('Page 2 of 16')).toBeInTheDocument()
  })

  it('rend une description <b>x</b> comme texte', async () => {
    const hostileAllowlist = { ...makeAllowlist('hostile', [makeEntry({ value: '192.0.2.30', description: '<b>entry</b>' })]), description: '<b>x</b>' }
    stubFetch(allowlistRoutes({ [`GET ${LOCAL_LISTING_URL}`]: makeListing('local', [hostileAllowlist]) }))
    const { container } = renderApp('/allowlists')

    const allowlistDescription = await screen.findByText('<b>x</b>')
    expect(allowlistDescription.tagName).toBe('BDI')
    expect(screen.getByText('<b>entry</b>').tagName).toBe('BDI')
    expect(container.querySelector('b')).toBeNull()
  })

  it('affiche l\'avis quand refreshed est faux', async () => {
    stubFetch(allowlistRoutes({ [`POST ${TRUSTED_ENTRIES_URL}`]: mutationResponse(201, false) }))
    const user = userEvent.setup()
    renderApp('/allowlists')

    const entryDialog = await openAddEntryDialog(user, 'trusted')
    await user.type(within(entryDialog).getByLabelText(en.allowlists.value), '192.0.2.44')
    await user.click(within(entryDialog).getByRole('button', { name: en.allowlists.entrySubmit }))

    expect(await screen.findByText(en.allowlists.refreshFailed)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('les fichiers de langue ont les mêmes clés', () => {
    expect(collectKeyPaths(fr.allowlists).sort()).toEqual(collectKeyPaths(en.allowlists).sort())
    expect(fr.nav.allowlists).toBeTruthy()
    for (const errorCode of ALLOWLIST_ERROR_CODES) {
      expect(en.errors[errorCode as keyof typeof en.errors], errorCode).toBeTruthy()
      expect(fr.errors[errorCode as keyof typeof fr.errors], errorCode).toBeTruthy()
    }
  })
})
