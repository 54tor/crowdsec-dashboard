import { QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactElement, ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { deleteBouncer } from '@/api/writeApi'
import { MachinesTable } from '@/components/HealthTables'
import { HubToolbar } from '@/components/HubToolbar'
import { ReloadBanner } from '@/components/ReloadBanner'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { ValidateMachineButton } from '@/components/ValidateMachineButton'
import { ReloadRequiredContext } from '@/hooks/ReloadRequiredContext'
import en from '@/i18n/en.json'
import { createQueryClient } from '@/queryClient'
import { stubFetch } from '@/test/fetchStub'
import { makeMachine } from '@/test/fixtures'
import { holdPostRequests, prepareEnglishApp, requestsTo } from '@/test/pageHarness'

// TanStack Query hands a pending mutation the options of the observer's latest
// render. Every test below starts a write on 'peer', re-renders the component on
// 'local' while the response is held, then releases it: the completion callbacks
// must still act on 'peer', the engine chosen when the button was clicked.

function renderWithWriteContext(initialElement: ReactElement) {
  const queryClient = createQueryClient()
  const invalidationSpy = vi.spyOn(queryClient, 'invalidateQueries')
  // Every engine is flagged so the reload banner stays visible whatever engine it is rendered for.
  const reloadRequired = {
    isReloadRequired: vi.fn(() => true),
    markReloadRequired: vi.fn(),
    clearReloadRequired: vi.fn(),
  }
  function WriteContextProviders({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <ReloadRequiredContext.Provider value={reloadRequired}>{children}</ReloadRequiredContext.Provider>
      </QueryClientProvider>
    )
  }
  const renderResult = render(initialElement, { wrapper: WriteContextProviders })
  return { ...renderResult, invalidationSpy, reloadRequired }
}

function invalidatedKeysOf(invalidationSpy: { mock: { calls: unknown[][] } }): unknown[] {
  return invalidationSpy.mock.calls.map(([invalidationFilters]) => (invalidationFilters as { queryKey?: unknown } | undefined)?.queryKey)
}

const SHARED_MACHINE_ID = 'shared-agent'

function machinesTableOn(engineName: string) {
  const unvalidatedMachine = makeMachine({ machine_id: SHARED_MACHINE_ID, is_validated: false })
  const validateAction = {
    header: en.machines.actions,
    cell: (machine: typeof unvalidatedMachine) => <ValidateMachineButton machineId={machine.machine_id} engineName={engineName} />,
  }
  return <MachinesTable engineName={engineName} machines={[unvalidatedMachine]} now={Date.now()} actions={validateAction} />
}

const REMOVED_BOUNCER_NAME = 'firewall-bouncer'

function bouncerRemovalOn(engineName: string, onDeleted: () => void) {
  return (
    <RowDeleteAction
      buttonLabel={en.common.delete}
      ariaLabel={`Delete ${REMOVED_BOUNCER_NAME}`}
      title={`Delete ${REMOVED_BOUNCER_NAME}`}
      description={`Delete ${REMOVED_BOUNCER_NAME} on ${engineName}`}
      target={REMOVED_BOUNCER_NAME}
      engineName={engineName}
      request={(confirm) => deleteBouncer(REMOVED_BOUNCER_NAME, confirm, engineName)}
      invalidates={[['bouncers', engineName]]}
      onDeleted={onDeleted}
    />
  )
}

describe('writes stay bound to the engine chosen at click time', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('hubUpdateFlagsAndRefreshesOnlyTheEngineItStartedOn', async () => {
    const fetchMock = stubFetch({})
    const heldUpdate = holdPostRequests(fetchMock)
    const user = userEvent.setup()
    const { rerender, invalidationSpy, reloadRequired } = renderWithWriteContext(<HubToolbar engineName="peer" />)

    await user.click(screen.getByRole('button', { name: en.hub.update }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/hub/update?engine=peer')).toHaveLength(1))
    rerender(<HubToolbar engineName="local" />)
    heldUpdate.settle(200, { status: 'updated' })

    await waitFor(() => expect(reloadRequired.markReloadRequired).toHaveBeenCalledTimes(1))
    expect(reloadRequired.markReloadRequired).toHaveBeenCalledWith('peer')
    expect(invalidatedKeysOf(invalidationSpy)).toEqual([['hub', 'peer']])
  })

  it('hubUpgradeTimeoutFlagsOnlyTheEngineItStartedOn', async () => {
    const fetchMock = stubFetch({})
    const heldUpgrade = holdPostRequests(fetchMock)
    const user = userEvent.setup()
    const { rerender, invalidationSpy, reloadRequired } = renderWithWriteContext(<HubToolbar engineName="peer" />)

    await user.click(screen.getByRole('button', { name: en.hub.upgrade }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/hub/upgrade?engine=peer')).toHaveLength(1))
    rerender(<HubToolbar engineName="local" />)
    heldUpgrade.settle(504, { error: 'cscli_timeout' })

    await waitFor(() => expect(reloadRequired.markReloadRequired).toHaveBeenCalledTimes(1))
    expect(reloadRequired.markReloadRequired).toHaveBeenCalledWith('peer')
    expect(invalidatedKeysOf(invalidationSpy)).toEqual([])
  })

  it('reloadCompletionClearsOnlyTheEngineThatWasReloaded', async () => {
    const fetchMock = stubFetch({})
    const heldReload = holdPostRequests(fetchMock)
    const user = userEvent.setup()
    const { rerender, reloadRequired } = renderWithWriteContext(<ReloadBanner engineName="peer" />)

    await user.click(screen.getByRole('button', { name: en.hub.reload }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/crowdsec/reload?engine=peer')).toHaveLength(1))
    rerender(<ReloadBanner engineName="local" />)
    heldReload.settle(200, { status: 'reloaded' })

    await waitFor(() => expect(reloadRequired.clearReloadRequired).toHaveBeenCalledTimes(1))
    expect(reloadRequired.clearReloadRequired).toHaveBeenCalledWith('peer')
  })

  // The same machine id exists on both engines: the row of the other engine must
  // not inherit the pending state of the validation started on the first one.
  it('machineValidationPendingStateAndRefreshStayOnTheirEngine', async () => {
    const fetchMock = stubFetch({})
    const heldValidation = holdPostRequests(fetchMock)
    const user = userEvent.setup()
    const { rerender, invalidationSpy } = renderWithWriteContext(machinesTableOn('peer'))
    const validateButtonName = en.machines.validateAria.replace('{{name}}', SHARED_MACHINE_ID)

    await user.click(screen.getByRole('button', { name: validateButtonName }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', `/api/machines/${SHARED_MACHINE_ID}/validate?engine=peer`)).toHaveLength(1))
    expect(screen.getByRole('button', { name: validateButtonName })).toBeDisabled()
    rerender(machinesTableOn('local'))

    const localValidateButton = screen.getByRole('button', { name: validateButtonName })
    expect(localValidateButton).toBeEnabled()
    expect(localValidateButton).toHaveTextContent(en.machines.validate)

    heldValidation.settle(200, { status: 'validated' })
    await waitFor(() => expect(invalidatedKeysOf(invalidationSpy)).toContainEqual(['machines', 'peer']))
    expect(invalidatedKeysOf(invalidationSpy)).not.toContainEqual(['machines', 'local'])
  })

  it('rowDeletionCallbacksStayOnTheEngineConfirmed', async () => {
    const fetchMock = stubFetch({})
    const heldDeletion = holdPostRequests(fetchMock)
    const user = userEvent.setup()
    const peerDeletedSpy = vi.fn()
    const localDeletedSpy = vi.fn()
    const { rerender, invalidationSpy } = renderWithWriteContext(bouncerRemovalOn('peer', peerDeletedSpy))

    await user.click(screen.getByRole('button', { name: `Delete ${REMOVED_BOUNCER_NAME}` }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(en.confirmDelete.label.replace('{{target}}', REMOVED_BOUNCER_NAME)), REMOVED_BOUNCER_NAME)
    await user.click(within(dialog).getByRole('button', { name: en.common.delete }))
    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', `/api/bouncers/${REMOVED_BOUNCER_NAME}?engine=peer`)).toHaveLength(1))
    rerender(bouncerRemovalOn('local', localDeletedSpy))
    heldDeletion.settle(200, { status: 'deleted' })

    await waitFor(() => expect(peerDeletedSpy).toHaveBeenCalledTimes(1))
    expect(localDeletedSpy).not.toHaveBeenCalled()
    expect(invalidatedKeysOf(invalidationSpy)).toEqual([['bouncers', 'peer']])
  })
})
