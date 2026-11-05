import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeMachine } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import {
  ENGINE_NAMES_WITH_SIDECARS,
  expectEveryWriteToTarget,
  expectNoEngineParameterAnywhere,
  selectTargetEngine,
  targetEngineNamedIn,
} from '@/test/engineTargetHarness'
import { holdPostRequests, prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const FAKE_PASSWORD = 'fake-machine-password-for-tests'

function machineEngineRoutes(extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
    'GET /api/machines': { status: 200, body: { items: [makeMachine({ machine_id: 'local-agent' })] } },
    'GET /api/machines?engine=peer': { status: 200, body: { items: [makeMachine({ machine_id: 'peer-agent', is_validated: false })] } },
    ...extraRoutes,
  }
}

async function createMachineNamed(user: ReturnType<typeof userEvent.setup>, machineName: string) {
  await user.click(await screen.findByRole('button', { name: en.machines.add }))
  const dialog = await screen.findByRole('dialog', { name: en.machines.addTitle })
  await user.type(within(dialog).getByLabelText(en.machines.nameLabel), machineName)
  await user.click(within(dialog).getByRole('button', { name: en.secret.create }))
  return dialog
}

describe('machines page engine target', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('localEngineKeepsTheUnparameterisedUrls', async () => {
    const fetchMock = stubFetch(machineEngineRoutes({ 'POST /api/machines': { status: 200, body: { name: 'new-machine', password: FAKE_PASSWORD } } }))
    const user = userEvent.setup()
    renderApp('/machines')
    await screen.findByLabelText(en.engineTarget.label)

    const dialog = await createMachineNamed(user, 'new-machine')

    expect(await within(dialog).findByText(FAKE_PASSWORD)).toBeInTheDocument()
    expect(targetEngineNamedIn(dialog)).toBe('local')
    expect(requestsTo(fetchMock, 'POST', '/api/machines')).toHaveLength(1)
    expectNoEngineParameterAnywhere(fetchMock)
  })

  it('validatesAndCreatesOnTheSelectedEngine', async () => {
    const fetchMock = stubFetch(machineEngineRoutes({
      'POST /api/machines/peer-agent/validate?engine=peer': { status: 200, body: { status: 'validated' } },
      'POST /api/machines?engine=peer': { status: 200, body: { name: 'new-machine', password: FAKE_PASSWORD } },
    }))
    const user = userEvent.setup()
    renderApp('/machines')

    await selectTargetEngine(user, 'peer')
    await user.click(await screen.findByRole('button', { name: 'Validate peer-agent' }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/machines/peer-agent/validate?engine=peer')).toHaveLength(1))
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/machines?engine=peer').length).toBeGreaterThan(1))

    const dialog = await createMachineNamed(user, 'new-machine')
    expect(targetEngineNamedIn(dialog)).toBe('peer')
    expect(await within(dialog).findByText(FAKE_PASSWORD)).toBeInTheDocument()

    expect(requestsTo(fetchMock, 'POST', '/api/machines')).toHaveLength(0)
    expectEveryWriteToTarget(fetchMock, 'peer')
  })

  it('engineSelectorIsLockedWhileAValidationIsPending', async () => {
    const fetchMock = stubFetch(machineEngineRoutes())
    const user = userEvent.setup()
    renderApp('/machines')

    await selectTargetEngine(user, 'peer')
    const heldValidation = holdPostRequests(fetchMock)
    await user.click(await screen.findByRole('button', { name: 'Validate peer-agent' }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/machines/peer-agent/validate?engine=peer')).toHaveLength(1))
    expect(screen.getByLabelText(en.engineTarget.label)).toBeDisabled()

    heldValidation.settle(200, { status: 'validated' })
    await waitFor(() => expect(screen.getByLabelText(en.engineTarget.label)).toBeEnabled())
  })
})
