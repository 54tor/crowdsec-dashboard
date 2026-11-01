import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeEngine } from '@/test/fixtures'
import { stubFetch, type RouteTable, type StubbedResponse } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }

const LOCAL_ENGINE = makeEngine({ name: 'local', is_local: true, lapi_url: 'http://crowdsec:8080', machine_id: 'local-machine' })
const REMOTE_ENGINE = makeEngine({
  name: 'remote-one',
  proxy: { kind: 'socks5', url: 'socks5://198.51.100.5:1080' },
  has_proxy_credentials: true,
})

function engineRoutes(extraRoutes: RouteTable = {}): RouteTable {
  return {
    'GET /api/auth/me': ADMIN_SESSION,
    'GET /api/engines': { status: 200, body: { items: [LOCAL_ENGINE, REMOTE_ENGINE] } },
    ...extraRoutes,
  }
}

function lastJsonBody(fetchMock: { mock: { calls: unknown[][] } }, method: string, url: string): Record<string, unknown> {
  const matchingRequests = requestsTo(fetchMock, method, url)
  return JSON.parse(String(matchingRequests[matchingRequests.length - 1].body))
}

async function openEditDialog(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Edit remote-one' }))
  return screen.findByRole('dialog')
}

describe('engines page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('liste les moteurs sans jamais afficher de secret', async () => {
    stubFetch(engineRoutes())
    const user = userEvent.setup()
    renderApp('/engines')

    expect(await screen.findByText('remote-one', { selector: 'td' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit local' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete local' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete remote-one' })).toBeInTheDocument()

    const remoteRow = screen.getByText('remote-one', { selector: 'td' }).closest('tr')!
    const destinationCell = within(remoteRow).getByText('https://lapi.example.com:8080').closest('td')!
    expect(destinationCell).toHaveTextContent(
      `https://lapi.example.com:8080Machine dashboard-machineProxy socks5 socks5://198.51.100.5:1080 (${en.engines.proxyCredentials})`,
    )

    const dialog = await openEditDialog(user)
    for (const secretLabel of [en.engines.fields.machinePassword, en.engines.fields.proxyUsername, en.engines.fields.proxyPassword]) {
      const secretField = within(dialog).getByLabelText(secretLabel)
      expect(secretField).toHaveValue('')
      expect(secretField).toHaveAttribute('autocomplete', 'new-password')
    }
  })

  it("masque la navigation Moteurs pour un compte read_only", async () => {
    stubFetch(engineRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION, 'GET /api/alerts': { status: 200, body: { items: [], total: 0 } } }))
    renderApp('/alerts')
    await screen.findByRole('navigation', { name: en.nav.label })
    await waitFor(() => expect(screen.getByRole('link', { name: en.nav.bouncers })).toBeInTheDocument())
    expect(screen.queryByRole('link', { name: en.nav.engines })).not.toBeInTheDocument()
  })

  it('affiche la navigation Moteurs pour un administrateur', async () => {
    stubFetch(engineRoutes({ 'GET /api/alerts': { status: 200, body: { items: [], total: 0 } } }))
    renderApp('/alerts')
    expect(await screen.findByRole('link', { name: en.nav.engines })).toBeInTheDocument()
  })

  it('redirige /engines pour un compte read_only', async () => {
    const fetchMock = stubFetch(engineRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION, 'GET /api/alerts': { status: 200, body: { items: [], total: 0 } } }))
    const { visitedPaths } = renderApp('/engines')
    await waitFor(() => expect(visitedPaths[visitedPaths.length - 1]).toBe('/alerts'))
    expect(requestsTo(fetchMock, 'GET', '/api/engines')).toHaveLength(0)
  })

  it("envoie machine_password seulement s'il est saisi en édition", async () => {
    const fetchMock = stubFetch(engineRoutes({ 'PATCH /api/engines/remote-one': { status: 200, body: REMOTE_ENGINE } }))
    const user = userEvent.setup()
    renderApp('/engines')

    let dialog = await openEditDialog(user)
    await user.clear(within(dialog).getByLabelText(en.engines.fields.machineId))
    await user.type(within(dialog).getByLabelText(en.engines.fields.machineId), 'renamed-machine')
    await user.click(within(dialog).getByRole('button', { name: en.engines.save }))
    await waitFor(() => expect(requestsTo(fetchMock, 'PATCH', '/api/engines/remote-one')).toHaveLength(1))
    const firstBody = lastJsonBody(fetchMock, 'PATCH', '/api/engines/remote-one')
    expect(firstBody).not.toHaveProperty('machine_password')
    expect(firstBody.machine_id).toBe('renamed-machine')
    expect(firstBody.proxy).toEqual({ kind: 'socks5', url: 'socks5://198.51.100.5:1080' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    dialog = await openEditDialog(user)
    await user.type(within(dialog).getByLabelText(en.engines.fields.machinePassword), 'typed-test-password')
    await user.click(within(dialog).getByRole('button', { name: en.engines.save }))
    await waitFor(() => expect(requestsTo(fetchMock, 'PATCH', '/api/engines/remote-one')).toHaveLength(2))
    expect(lastJsonBody(fetchMock, 'PATCH', '/api/engines/remote-one').machine_password).toBe('typed-test-password')
  })

  it("exige le mot de passe machine quand l'URL change", async () => {
    const fetchMock = stubFetch(engineRoutes({ 'PATCH /api/engines/remote-one': { status: 200, body: REMOTE_ENGINE } }))
    const user = userEvent.setup()
    renderApp('/engines')

    const dialog = await openEditDialog(user)
    await user.clear(within(dialog).getByLabelText(en.engines.fields.lapiUrl))
    await user.type(within(dialog).getByLabelText(en.engines.fields.lapiUrl), 'https://other.example.com:8080')

    expect(within(dialog).getByRole('button', { name: en.engines.save })).toBeDisabled()
    expect(within(dialog).getByLabelText(en.engines.fields.machinePassword)).toHaveAccessibleDescription(
      new RegExp(en.engines.fields.machinePasswordRequired),
    )
    expect(requestsTo(fetchMock, 'PATCH', '/api/engines/remote-one')).toHaveLength(0)

    await user.type(within(dialog).getByLabelText(en.engines.fields.machinePassword), 'typed-test-password')
    await user.click(within(dialog).getByRole('button', { name: en.engines.save }))
    await waitFor(() => expect(requestsTo(fetchMock, 'PATCH', '/api/engines/remote-one')).toHaveLength(1))
  })

  it('exige les identifiants du proxy quand son URL change', async () => {
    stubFetch(engineRoutes())
    const user = userEvent.setup()
    renderApp('/engines')

    const dialog = await openEditDialog(user)
    await user.clear(within(dialog).getByLabelText(en.engines.fields.proxyUrl))
    await user.type(within(dialog).getByLabelText(en.engines.fields.proxyUrl), 'socks5://198.51.100.6:1080')
    expect(within(dialog).getByRole('button', { name: en.engines.save })).toBeDisabled()

    await user.click(within(dialog).getByLabelText(en.engines.fields.clearProxyCredentials))
    expect(within(dialog).getByRole('button', { name: en.engines.save })).toBeEnabled()
  })

  it('exige la ressaisie du nom pour supprimer', async () => {
    const fetchMock = stubFetch(engineRoutes({ 'DELETE /api/engines/remote-one': { status: 200, body: { status: 'deleted' } } }))
    const user = userEvent.setup()
    renderApp('/engines')

    await user.click(await screen.findByRole('button', { name: 'Delete remote-one' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/also deletes its whole archive/)).toBeInTheDocument()
    const submitButton = within(dialog).getByRole('button', { name: en.common.delete })
    expect(submitButton).toBeDisabled()
    await user.type(within(dialog).getByLabelText('Type remote-one to confirm'), 'remote-one')
    await user.click(submitButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/engines/remote-one')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'DELETE', '/api/engines/remote-one')[0].body).toBe('{"confirm":"remote-one"}')
  })

  it('affiche le résultat du test de connexion traduit', async () => {
    const testOutcomes: StubbedResponse[] = [
      { status: 200, body: { status: 'ok' } },
      { status: 502, body: { error: 'engine_unreachable' } },
    ]
    stubFetch(engineRoutes({ 'POST /api/engines/remote-one/test': () => testOutcomes.shift()! }))
    const user = userEvent.setup()
    renderApp('/engines')

    await user.click(await screen.findByRole('button', { name: 'Test remote-one' }))
    expect(await screen.findByText(en.engines.testOk)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Test remote-one' }))
    expect(await screen.findByText(en.errors.engine_unreachable)).toBeInTheDocument()
  })

  it('traduit engine_blocked_address, engine_secret_required et forbidden', async () => {
    const createOutcomes: StubbedResponse[] = [
      { status: 400, body: { error: 'engine_blocked_address' } },
      { status: 400, body: { error: 'engine_secret_required' } },
      { status: 403, body: { error: 'forbidden' } },
    ]
    stubFetch(engineRoutes({ 'POST /api/engines': () => createOutcomes.shift()! }))
    const user = userEvent.setup()
    renderApp('/engines')

    await user.click(await screen.findByRole('button', { name: en.engines.add }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(en.engines.fields.name), 'new-engine')
    await user.type(within(dialog).getByLabelText(en.engines.fields.lapiUrl), 'https://lapi.example.com:8080')
    await user.type(within(dialog).getByLabelText(en.engines.fields.machineId), 'machine')
    await user.type(within(dialog).getByLabelText(en.engines.fields.machinePassword), 'typed-test-password')
    const fetchMock = vi.mocked(fetch)
    for (const expectedMessage of [en.errors.engine_blocked_address, en.errors.engine_secret_required, en.errors.forbidden]) {
      await user.click(within(dialog).getByRole('button', { name: en.engines.create }))
      expect(await within(dialog).findByText(expectedMessage)).toBeInTheDocument()
    }
    expect(lastJsonBody(fetchMock, 'POST', '/api/engines').machine_password).toBe('typed-test-password')
  })

  it("affiche l'état de collecte et l'avertissement de rechargement", async () => {
    const collectedEngine = makeEngine({
      name: 'remote-one',
      collection: { ...REMOTE_ENGINE.collection, last_collected_at: '2026-10-31T10:00:00Z', last_error_code: 'engine_secret_unreadable', gaps: 2 },
    })
    stubFetch(
      engineRoutes({
        'GET /api/engines': { status: 200, body: { items: [LOCAL_ENGINE, collectedEngine] } },
        'DELETE /api/engines/remote-one': { status: 200, body: { status: 'deleted', warning: 'registry_reload_failed' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/engines')

    expect(await screen.findByText(en.errors.engine_secret_unreadable)).toBeInTheDocument()
    expect(screen.getByText(en.engines.status.incomplete)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Delete remote-one' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Type remote-one to confirm'), 'remote-one')
    await user.click(within(dialog).getByRole('button', { name: en.common.delete }))
    expect(await screen.findByText(en.errors.registry_reload_failed)).toBeInTheDocument()
  })

  it('exige le mot de passe machine pour un changement de proxy seul sur un moteur http', async () => {
    const httpEngine = makeEngine({
      name: 'remote-one',
      lapi_url: 'http://lapi.example.com:8080',
      allow_insecure_http: true,
      proxy: { kind: 'socks5', url: 'socks5://198.51.100.5:1080' },
    })
    stubFetch(engineRoutes({ 'GET /api/engines': { status: 200, body: { items: [httpEngine] } } }))
    const user = userEvent.setup()
    renderApp('/engines')

    const dialog = await openEditDialog(user)
    await user.clear(within(dialog).getByLabelText(en.engines.fields.proxyUrl))
    await user.type(within(dialog).getByLabelText(en.engines.fields.proxyUrl), 'socks5://198.51.100.6:1080')
    expect(within(dialog).getByRole('button', { name: en.engines.save })).toBeDisabled()
    await user.type(within(dialog).getByLabelText(en.engines.fields.machinePassword), 'typed-test-password')
    expect(within(dialog).getByRole('button', { name: en.engines.save })).toBeEnabled()
  })

  it('ne exige pas le mot de passe machine pour un changement de proxy seul sur un moteur https', async () => {
    stubFetch(engineRoutes())
    const user = userEvent.setup()
    renderApp('/engines')

    const dialog = await openEditDialog(user)
    await user.clear(within(dialog).getByLabelText(en.engines.fields.proxyUrl))
    await user.type(within(dialog).getByLabelText(en.engines.fields.proxyUrl), 'socks5://198.51.100.6:1080')
    await user.click(within(dialog).getByLabelText(en.engines.fields.clearProxyCredentials))
    expect(within(dialog).getByRole('button', { name: en.engines.save })).toBeEnabled()
  })

  it('masque la navigation Moteurs tant que le rôle est inconnu', async () => {
    stubFetch(engineRoutes({ 'GET /api/auth/me': { status: 200, body: { status: 'ok' } }, 'GET /api/alerts': { status: 200, body: { items: [], total: 0 } } }))
    renderApp('/alerts')
    await waitFor(() => expect(screen.getByRole('link', { name: en.nav.bouncers })).toBeInTheDocument())
    expect(screen.queryByRole('link', { name: en.nav.engines })).not.toBeInTheDocument()
  })

  it('redirige /engines tant que le rôle est inconnu', async () => {
    const fetchMock = stubFetch(engineRoutes({ 'GET /api/auth/me': { status: 200, body: { status: 'ok' } }, 'GET /api/alerts': { status: 200, body: { items: [], total: 0 } } }))
    const { visitedPaths } = renderApp('/engines')
    await waitFor(() => expect(visitedPaths[visitedPaths.length - 1]).toBe('/alerts'))
    expect(requestsTo(fetchMock, 'GET', '/api/engines')).toHaveLength(0)
  })
})
