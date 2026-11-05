import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeHubItem } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import {
  ENGINE_NAMES_WITH_SIDECARS,
  expectEveryWriteToTarget,
  holdRequestsTo,
  offeredEngineNames,
  selectTargetEngine,
  targetEngineNamedIn,
} from '@/test/engineTargetHarness'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }
const LOCAL_ITEM_NAME = 'crowdsecurity/linux'
const PEER_ITEM_NAME = 'crowdsecurity/nginx'

function hubEngineRoutes(extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
    'GET /api/hub': { status: 200, body: [makeHubItem({ type: 'collections', name: LOCAL_ITEM_NAME })] },
    'GET /api/hub?engine=peer': { status: 200, body: [makeHubItem({ type: 'collections', name: PEER_ITEM_NAME })] },
    ...extraRoutes,
  }
}

async function installOnOpenDialog(user: ReturnType<typeof userEvent.setup>, itemName: string) {
  await user.click(screen.getByRole('button', { name: en.hub.install }))
  const dialog = await screen.findByRole('dialog', { name: en.hub.installTitle })
  expect(targetEngineNamedIn(dialog)).toBe('peer')
  await user.type(within(dialog).getByLabelText(en.hub.installName), itemName)
  await user.click(within(dialog).getByRole('button', { name: en.hub.installSubmit }))
}

describe('hub page engine target', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('installsAHubItemOnTheSelectedEngine', async () => {
    const fetchMock = stubFetch(hubEngineRoutes({ 'POST /api/hub/collections?engine=peer': { status: 200, body: { status: 'installed' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    await selectTargetEngine(user, 'peer')
    await screen.findByText(PEER_ITEM_NAME, { selector: 'td' })
    await installOnOpenDialog(user, 'crowdsecurity/sshd')

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/hub/collections?engine=peer')).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/hub/collections?engine=peer')[0].body))).toEqual({ name: 'crowdsecurity/sshd' })
    expect(requestsTo(fetchMock, 'POST', '/api/hub/collections')).toHaveLength(0)
    expectEveryWriteToTarget(fetchMock, 'peer')
  })

  it('selectorOffersOnlyEnginesWithSidecar', async () => {
    stubFetch(hubEngineRoutes())
    renderApp('/hub')

    await screen.findByLabelText(en.engineTarget.label)

    expect(offeredEngineNames()).toEqual(['local', 'peer'])
    expect((screen.getByLabelText(en.engineTarget.label) as HTMLSelectElement).value).toBe('local')
  })

  it('selectorIsHiddenWhileEngineNamesLoad', async () => {
    const fetchMock = stubFetch(hubEngineRoutes())
    const heldEngineNames = holdRequestsTo(fetchMock, '/api/engines/names')
    renderApp('/hub')

    await screen.findByText(LOCAL_ITEM_NAME, { selector: 'td' })
    expect(screen.queryByLabelText(en.engineTarget.label)).toBeNull()

    heldEngineNames.settle(ENGINE_NAMES_WITH_SIDECARS.status, ENGINE_NAMES_WITH_SIDECARS.body)
    expect(await screen.findByLabelText(en.engineTarget.label)).toBeInTheDocument()
  })

  // The peer list is held: between the switch and its arrival the page must not
  // keep showing the local rows under the peer selection.
  it('switchingEngineNeverShowsThePreviousEnginesRows', async () => {
    const fetchMock = stubFetch(hubEngineRoutes())
    const user = userEvent.setup()
    renderApp('/hub')
    await screen.findByText(LOCAL_ITEM_NAME, { selector: 'td' })
    const heldPeerList = holdRequestsTo(fetchMock, '/api/hub?engine=peer')

    await selectTargetEngine(user, 'peer')

    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/hub?engine=peer')).toHaveLength(1))
    expect(screen.queryByText(LOCAL_ITEM_NAME, { selector: 'td' })).toBeNull()
    expect(screen.queryByRole('button', { name: en.hub.removeAria.replace('{{name}}', LOCAL_ITEM_NAME) })).toBeNull()

    heldPeerList.settle(200, [makeHubItem({ type: 'collections', name: PEER_ITEM_NAME })])
    expect(await screen.findByText(PEER_ITEM_NAME, { selector: 'td' })).toBeInTheDocument()
    expect(screen.queryByText(LOCAL_ITEM_NAME, { selector: 'td' })).toBeNull()
  })

  it('removeDialogNamesTheTargetEngine', async () => {
    const removeUrl = `/api/hub/collections/${PEER_ITEM_NAME}?engine=peer`
    const fetchMock = stubFetch(hubEngineRoutes({ [`DELETE ${removeUrl}`]: { status: 200, body: { status: 'deleted' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    await selectTargetEngine(user, 'peer')
    await user.click(await screen.findByRole('button', { name: en.hub.removeAria.replace('{{name}}', PEER_ITEM_NAME) }))
    const dialog = await screen.findByRole('dialog')
    expect(targetEngineNamedIn(dialog)).toBe('peer')
    await user.type(within(dialog).getByLabelText(en.confirmDelete.label.replace('{{target}}', PEER_ITEM_NAME)), PEER_ITEM_NAME)
    await user.click(within(dialog).getByRole('button', { name: en.hub.remove }))

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', removeUrl)).toHaveLength(1))
    expectEveryWriteToTarget(fetchMock, 'peer')
  })

  it('reloadIsRequiredOnlyOnTheEngineThatChanged', async () => {
    const fetchMock = stubFetch(hubEngineRoutes({
      'POST /api/hub/update?engine=peer': { status: 200, body: { status: 'updated' } },
      'POST /api/crowdsec/reload?engine=peer': { status: 200, body: { status: 'reloaded' } },
    }))
    const user = userEvent.setup()
    renderApp('/hub')

    await selectTargetEngine(user, 'peer')
    await user.click(await screen.findByRole('button', { name: en.hub.update }))
    const banner = (await screen.findByText(en.hub.reloadRequired)).closest('[role="status"]') as HTMLElement
    expect(targetEngineNamedIn(banner)).toBe('peer')

    await selectTargetEngine(user, 'local')
    expect(screen.queryByText(en.hub.reloadRequired)).toBeNull()

    await selectTargetEngine(user, 'peer')
    await user.click(await screen.findByRole('button', { name: en.hub.reload }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/crowdsec/reload?engine=peer')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'POST', '/api/crowdsec/reload')).toHaveLength(0)
    expectEveryWriteToTarget(fetchMock, 'peer')
  })

  it('readOnlyAccountSeesNoWriteActionOnASelectedEngine', async () => {
    stubFetch(hubEngineRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION }))
    const user = userEvent.setup()
    renderApp('/hub')

    await selectTargetEngine(user, 'peer')
    await screen.findByText(PEER_ITEM_NAME, { selector: 'td' })

    expect(screen.queryByRole('button', { name: en.hub.install })).toBeNull()
    expect(screen.queryByRole('button', { name: en.hub.update })).toBeNull()
    expect(screen.queryByRole('button', { name: en.hub.removeAria.replace('{{name}}', PEER_ITEM_NAME) })).toBeNull()
  })
})
