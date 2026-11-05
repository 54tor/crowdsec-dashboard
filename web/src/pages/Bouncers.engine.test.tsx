import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeBouncer } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { ENGINE_NAMES_WITH_SIDECARS, expectEveryWriteToTarget, holdRequestsTo, selectTargetEngine, targetEngineNamedIn } from '@/test/engineTargetHarness'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }
const FAKE_KEY = 'fake-remote-bouncer-key-for-tests'

function bouncerEngineRoutes(extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
    'GET /api/bouncers': { status: 200, body: { items: [makeBouncer({ name: 'local-firewall' })] } },
    'GET /api/bouncers?engine=peer': { status: 200, body: { items: [makeBouncer({ name: 'peer-firewall' })] } },
    ...extraRoutes,
  }
}

describe('bouncers page engine target', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('listsBouncersOfTheSelectedEngine', async () => {
    const fetchMock = stubFetch(bouncerEngineRoutes())
    const user = userEvent.setup()
    renderApp('/bouncers')
    await screen.findByText('local-firewall', { selector: 'td' })

    await selectTargetEngine(user, 'peer')

    expect(await screen.findByText('peer-firewall', { selector: 'td' })).toBeInTheDocument()
    expect(screen.queryByText('local-firewall', { selector: 'td' })).toBeNull()
    expect(requestsTo(fetchMock, 'GET', '/api/bouncers?engine=peer')).toHaveLength(1)
    expect(requestsTo(fetchMock, 'GET', '/api/health')).toHaveLength(0)
  })

  it('switchingEngineNeverShowsThePreviousEnginesRows', async () => {
    const fetchMock = stubFetch(bouncerEngineRoutes())
    const user = userEvent.setup()
    renderApp('/bouncers')
    await screen.findByText('local-firewall', { selector: 'td' })
    const heldPeerList = holdRequestsTo(fetchMock, '/api/bouncers?engine=peer')

    await selectTargetEngine(user, 'peer')

    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/bouncers?engine=peer')).toHaveLength(1))
    expect(screen.queryByText('local-firewall', { selector: 'td' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete local-firewall' })).toBeNull()

    heldPeerList.settle(200, { items: [makeBouncer({ name: 'peer-firewall' })] })
    expect(await screen.findByText('peer-firewall', { selector: 'td' })).toBeInTheDocument()
  })

  it('createsAndDeletesABouncerOnTheSelectedEngine', async () => {
    const fetchMock = stubFetch(bouncerEngineRoutes({
      'POST /api/bouncers?engine=peer': { status: 200, body: { name: 'new-one', key: FAKE_KEY } },
      'DELETE /api/bouncers/peer-firewall?engine=peer': { status: 200, body: { status: 'deleted' } },
    }))
    const user = userEvent.setup()
    renderApp('/bouncers')
    await selectTargetEngine(user, 'peer')
    await screen.findByText('peer-firewall', { selector: 'td' })

    await user.click(screen.getByRole('button', { name: en.bouncers.add }))
    const createDialog = await screen.findByRole('dialog', { name: en.bouncers.addTitle })
    expect(targetEngineNamedIn(createDialog)).toBe('peer')
    await user.type(within(createDialog).getByLabelText(en.bouncers.nameLabel), 'new-one')
    await user.click(within(createDialog).getByRole('button', { name: en.secret.create }))
    await within(createDialog).findByText(FAKE_KEY)
    await user.click(within(createDialog).getByRole('button', { name: en.secret.done }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())

    await user.click(screen.getByRole('button', { name: 'Delete peer-firewall' }))
    const deleteDialog = await screen.findByRole('dialog')
    expect(targetEngineNamedIn(deleteDialog)).toBe('peer')
    await user.type(within(deleteDialog).getByLabelText('Type peer-firewall to confirm'), 'peer-firewall')
    await user.click(within(deleteDialog).getByRole('button', { name: en.common.delete }))

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/bouncers/peer-firewall?engine=peer')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'POST', '/api/bouncers?engine=peer')).toHaveLength(1)
    expectEveryWriteToTarget(fetchMock, 'peer')
  })

  it('readOnlyAccountSeesNoWriteActionOnASelectedEngine', async () => {
    stubFetch(bouncerEngineRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION }))
    const user = userEvent.setup()
    renderApp('/bouncers')

    await selectTargetEngine(user, 'peer')
    await screen.findByText('peer-firewall', { selector: 'td' })

    expect(screen.queryByRole('button', { name: en.bouncers.add })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete peer-firewall' })).toBeNull()
  })
})
