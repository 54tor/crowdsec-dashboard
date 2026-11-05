import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeMachine } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const FAKE_PASSWORD = 'fake-machine-password-for-tests'

function machineRoutes(extraRoutes = {}) {
  const machines = [makeMachine({ machine_id: 'machine-one' }), makeMachine({ machine_id: 'machine-two', is_validated: false })]
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/machines': { status: 200, body: { items: machines } },
    ...extraRoutes,
  }
}

describe('machines page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('offersValidateOnlyForUnvalidatedMachines', async () => {
    const fetchMock = stubFetch(machineRoutes({ 'POST /api/machines/machine-two/validate': { status: 200, body: { status: 'validated' } } }))
    const user = userEvent.setup()
    renderApp('/machines')

    expect(await screen.findAllByRole('button', { name: /^Validate / })).toHaveLength(1)
    await user.click(screen.getByRole('button', { name: 'Validate machine-two' }))

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/machines/machine-two/validate')).toHaveLength(1))
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/machines').length).toBeGreaterThan(1))
  })

  it('filtersMachinesByAnyDisplayedText', async () => {
    stubFetch(machineRoutes())
    const user = userEvent.setup()
    renderApp('/machines')
    await screen.findByText('machine-two', { selector: 'td span' })

    // Only machine-two shows the translated "Not validated" badge.
    await user.type(screen.getByLabelText(en.clientFilter.label), en.health.notValidated.toUpperCase())

    expect(screen.queryByText('machine-one', { selector: 'td span' })).toBeNull()
    expect(screen.getByText('machine-two', { selector: 'td span' })).toBeInTheDocument()
    expect(await screen.findByText('1 of 2')).toBeInTheDocument()

    await user.clear(screen.getByLabelText(en.clientFilter.label))
    await user.type(screen.getByLabelText(en.clientFilter.label), 'no-such-machine')

    expect(screen.getByText(en.clientFilter.noMatch)).toBeInTheDocument()
    expect(screen.queryByText(en.health.noMachines)).toBeNull()
  })

  it('machinePasswordIsShownOnceThenClearedWhenDialogCloses', async () => {
    stubFetch(machineRoutes({ 'POST /api/machines': { status: 200, body: { name: 'new-machine', password: FAKE_PASSWORD } } }))
    const user = userEvent.setup()
    const { queryClient } = renderApp('/machines')

    await user.click(await screen.findByRole('button', { name: en.machines.add }))
    const dialog = await screen.findByRole('dialog', { name: en.machines.addTitle })
    await user.type(within(dialog).getByLabelText(en.machines.nameLabel), 'new-machine')
    await user.click(within(dialog).getByRole('button', { name: en.secret.create }))
    expect(await within(dialog).findByText(FAKE_PASSWORD)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: en.secret.done }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.body.innerHTML).not.toContain(FAKE_PASSWORD)
    expect(JSON.stringify(queryClient.getMutationCache().getAll())).not.toContain(FAKE_PASSWORD)
  })

  it('selfMachineShowsBadgeNoStaleAndDisabledDelete', async () => {
    const machines = [makeMachine({ machine_id: 'dashboard-machine', last_heartbeat: null, self: true }), makeMachine({ machine_id: 'machine-two' })]
    stubFetch(machineRoutes({ 'GET /api/machines': { status: 200, body: { items: machines } } }))
    renderApp('/machines')

    const selfRow = (await screen.findByText('dashboard-machine')).closest('tr') as HTMLElement
    expect(within(selfRow).getByText(en.health.self)).toBeInTheDocument()
    expect(within(selfRow).queryByText(en.health.stale)).not.toBeInTheDocument()
    expect(within(selfRow).queryByText(en.health.never)).not.toBeInTheDocument()
    expect(within(selfRow).queryByText(en.health.ok)).not.toBeInTheDocument()
    expect(within(selfRow).getByText(en.health.validated)).toBeInTheDocument()
    const deleteButton = within(selfRow).getByRole('button', { name: 'Delete dashboard-machine' })
    const visibleReason = within(selfRow).getByText(en.machines.selfDeleteReason)
    expect(deleteButton).toBeDisabled()
    expect(deleteButton).toHaveAttribute('aria-describedby', visibleReason.id)
    expect(visibleReason.id).not.toBe('')
    const otherRow = screen.getByText('machine-two').closest('tr') as HTMLElement
    expect(within(otherRow).getByText(en.health.stale)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete machine-two' })).toBeEnabled()
  })

  it('selfAccountDeletionShowsTranslatedExplanation', async () => {
    stubFetch(machineRoutes({ 'DELETE /api/machines/machine-one': { status: 409, body: { error: 'self_account' } } }))
    const user = userEvent.setup()
    renderApp('/machines')

    await user.click(await screen.findByRole('button', { name: 'Delete machine-one' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Type machine-one to confirm'), 'machine-one')
    await user.click(within(dialog).getByRole('button', { name: en.common.delete }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(en.errors.self_account)
    expect(within(dialog).getByRole('button', { name: en.common.delete })).toBeEnabled()
  })

  it('deleteMachineSendsConfirmWithNameOnly', async () => {
    const fetchMock = stubFetch(machineRoutes({ 'DELETE /api/machines/machine-two': { status: 200, body: { status: 'deleted' } } }))
    const user = userEvent.setup()
    renderApp('/machines')

    await user.click(await screen.findByRole('button', { name: 'Delete machine-two' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Type machine-two to confirm'), 'machine-two')
    await user.click(within(dialog).getByRole('button', { name: en.common.delete }))

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/machines/machine-two')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'DELETE', '/api/machines/machine-two')[0].body).toBe('{"confirm":"machine-two"}')
  })
})
