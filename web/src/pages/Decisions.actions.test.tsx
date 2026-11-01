import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeDecision, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { holdPostRequests, prepareEnglishApp, requestsTo, SESSION_OK, slowResponse } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const DECISIONS_URL = 'GET /api/decisions?page=1&per_page=20'

function decisionRoutes(extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    [DECISIONS_URL]: { status: 200, body: makePage([makeDecision({ id: 10, alert_id: 1 })]) },
    ...extraRoutes,
  }
}

async function openBanDialog(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: en.ban.open }))
  return screen.findByRole('dialog', { name: en.ban.title })
}

describe('decision actions', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('unbanStaysDisabledUntilTheIpIsRetypedExactly', async () => {
    stubFetch(decisionRoutes())
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: 'Unban 203.0.113.7' }))
    const dialog = await screen.findByRole('dialog')
    const confirmButton = within(dialog).getByRole('button', { name: en.decisions.unban })
    const confirmInput = within(dialog).getByLabelText('Type 203.0.113.7 to confirm')

    expect(confirmButton).toBeDisabled()
    await user.type(confirmInput, '203.0.113')
    expect(confirmButton).toBeDisabled()
    await user.clear(confirmInput)
    await user.type(confirmInput, '10')
    expect(confirmButton).toBeDisabled()
    await user.clear(confirmInput)
    await user.type(confirmInput, '203.0.113.7')
    expect(confirmButton).toBeEnabled()
    await user.type(confirmInput, '0')
    expect(confirmButton).toBeDisabled()
  })

  it('unbanOfARangeRequiresTheExactRangeAndStillSendsTheDecisionId', async () => {
    const rangeDecision = makeDecision({ id: 11, alert_id: 1, scope: 'Range', value: '198.51.100.0/24' })
    const fetchMock = stubFetch(
      decisionRoutes({
        [DECISIONS_URL]: { status: 200, body: makePage([rangeDecision]) },
        'DELETE /api/decisions/11?scope=Range&value=198.51.100.0%2F24': { status: 200, body: { status: 'deleted' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: 'Unban 198.51.100.0/24' }))
    const dialog = await screen.findByRole('dialog')
    const confirmButton = within(dialog).getByRole('button', { name: en.decisions.unban })
    const confirmInput = within(dialog).getByLabelText('Type 198.51.100.0/24 to confirm')
    await user.type(confirmInput, '198.51.100.0')
    expect(confirmButton).toBeDisabled()
    await user.type(confirmInput, '/24')
    expect(confirmButton).toBeEnabled()
    await user.click(confirmButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/decisions/11?scope=Range&value=198.51.100.0%2F24')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'DELETE', '/api/decisions/11?scope=Range&value=198.51.100.0%2F24')[0].body).toBe('{"confirm":"11"}')
  })

  it('unbanSendsOnlyConfirmBodyAtDecisionIdPathThenRefreshesList', async () => {
    const fetchMock = stubFetch(decisionRoutes({ 'DELETE /api/decisions/10?scope=Ip&value=203.0.113.7': { status: 200, body: { status: 'deleted' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: 'Unban 203.0.113.7' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Type 203.0.113.7 to confirm'), '203.0.113.7')
    await user.click(within(dialog).getByRole('button', { name: en.decisions.unban }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    const deleteRequests = requestsTo(fetchMock, 'DELETE', '/api/decisions/10?scope=Ip&value=203.0.113.7')
    expect(deleteRequests).toHaveLength(1)
    expect(deleteRequests[0].body).toBe('{"confirm":"10"}')
    expect(deleteRequests[0].credentials).toBe('same-origin')
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/decisions?page=1&per_page=20').length).toBeGreaterThan(1))
  })

  // Archived decisions and decisions of a remote engine may reuse the id of an
  // unrelated live local decision: only live local rows offer the unban.
  it('offersUnbanOnlyOnLiveLocalRows', async () => {
    const decisionRows = [
      makeDecision({ id: 30, value: '203.0.113.30', engine: 'edge-1', live: false }),
      makeDecision({ id: 20, value: '203.0.113.20', engine: 'local', live: false }),
      makeDecision({ id: 10, value: '203.0.113.10', engine: 'local', live: true }),
    ]
    stubFetch(decisionRoutes({ [DECISIONS_URL]: { status: 200, body: makePage(decisionRows) } }))
    renderApp('/decisions')

    expect(await screen.findByRole('button', { name: 'Unban 203.0.113.10' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Unban 203.0.113.30' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Unban 203.0.113.20' })).not.toBeInTheDocument()
  })

  it('escapeClosesConfirmDialogAndReturnsFocusToRowButton', async () => {
    stubFetch(decisionRoutes())
    const user = userEvent.setup()
    renderApp('/decisions')

    const rowButton = await screen.findByRole('button', { name: 'Unban 203.0.113.7' })
    await user.click(rowButton)
    await screen.findByRole('dialog')
    await user.keyboard('{Escape}')

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(rowButton).toHaveFocus())
  })

  it('unbanErrorIsTranslatedAndDialogIsNotStuckPending', async () => {
    stubFetch(decisionRoutes({ 'DELETE /api/decisions/10?scope=Ip&value=203.0.113.7': { status: 502, body: { error: 'lapi_unavailable' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: 'Unban 203.0.113.7' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Type 203.0.113.7 to confirm'), '203.0.113.7')
    await user.click(within(dialog).getByRole('button', { name: en.decisions.unban }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(en.errors.lapi_unavailable)
    expect(within(dialog).getByRole('button', { name: en.decisions.unban })).toBeEnabled()
  })

  it('unbanTargetMismatchShowsTheTranslatedReloadMessage', async () => {
    stubFetch(decisionRoutes({ 'DELETE /api/decisions/10?scope=Ip&value=203.0.113.7': { status: 409, body: { error: 'target_mismatch' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: 'Unban 203.0.113.7' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Type 203.0.113.7 to confirm'), '203.0.113.7')
    await user.click(within(dialog).getByRole('button', { name: en.decisions.unban }))

    const alertText = await within(dialog).findByRole('alert')
    expect(alertText).toHaveTextContent(en.errors.target_mismatch)
    expect(alertText).not.toHaveTextContent(en.errors.unknown)
  })

  it('banDialogShowsSelfBanErrorTranslated', async () => {
    stubFetch(decisionRoutes({ 'POST /api/decisions': { status: 409, body: { error: 'self_ban' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    const dialog = await openBanDialog(user)
    await user.type(within(dialog).getByLabelText(en.ban.ip), '198.51.100.7')
    await user.click(within(dialog).getByRole('button', { name: en.ban.submit }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(en.errors.self_ban)
  })

  it('banDialogShowsApiErrorTranslated', async () => {
    stubFetch(decisionRoutes({ 'POST /api/decisions': { status: 400, body: { error: 'invalid_target' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    const dialog = await openBanDialog(user)
    await user.type(within(dialog).getByLabelText(en.ban.ip), '203.0.113.9')
    await user.click(within(dialog).getByRole('button', { name: en.ban.submit }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(en.errors.invalid_target)
    expect(within(dialog).getByRole('button', { name: en.ban.submit })).toBeEnabled()
  })

  it.each(['1.2.3.4/33', '::ffff:1.2.3.4', 'a'.repeat(44), '0.0.0.0/0'])(
    'banDialogRejectsInvalidTargetInlineAndKeepsSubmitDisabled %s',
    async (invalidTarget) => {
      const fetchMock = stubFetch(decisionRoutes())
      const user = userEvent.setup()
      renderApp('/decisions')

      const dialog = await openBanDialog(user)
      const targetInput = within(dialog).getByLabelText(en.ban.ip)
      await user.type(targetInput, invalidTarget)

      expect(targetInput).toHaveAttribute('aria-invalid', 'true')
      expect(targetInput).toHaveAccessibleDescription(en.errors.invalid_target)
      expect(within(dialog).getByRole('button', { name: en.ban.submit })).toBeDisabled()
      expect(requestsTo(fetchMock, 'POST', '/api/decisions')).toHaveLength(0)
    },
  )

  it('banSendsIpDurationAndReasonThenRefreshesDecisions', async () => {
    const fetchMock = stubFetch(decisionRoutes({ 'POST /api/decisions': { status: 201, body: { status: 'created' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    const dialog = await openBanDialog(user)
    await user.type(within(dialog).getByLabelText(en.ban.ip), '203.0.113.9')
    await user.click(within(dialog).getByRole('button', { name: '7d' }))
    await user.type(within(dialog).getByLabelText(en.ban.reason), 'manual ban')
    await user.click(within(dialog).getByRole('button', { name: en.ban.submit }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    const banRequests = requestsTo(fetchMock, 'POST', '/api/decisions')
    expect(JSON.parse(String(banRequests[0].body))).toEqual({ ip: '203.0.113.9', duration: '7d', reason: 'manual ban' })
    expect(await screen.findByText('203.0.113.9 banned.')).toBeInTheDocument()
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/decisions?page=1&per_page=20').length).toBeGreaterThan(1))
  })

  it('banDoubleSubmitSendsOneRequest', async () => {
    const fetchMock = stubFetch(decisionRoutes())
    const defaultImplementation = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (input, init) =>
      init?.method === 'POST' ? slowResponse(201, { status: 'created' }, 50) : defaultImplementation(input, init),
    )
    const user = userEvent.setup()
    renderApp('/decisions')

    const dialog = await openBanDialog(user)
    await user.type(within(dialog).getByLabelText(en.ban.ip), '203.0.113.9')
    await user.dblClick(within(dialog).getByRole('button', { name: en.ban.submit }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(requestsTo(fetchMock, 'POST', '/api/decisions')).toHaveLength(1)
  })

  it('confirmDeleteDialogCannotBeClosedWhilePending', async () => {
    const fetchMock = stubFetch(decisionRoutes())
    const heldResponse = holdPostRequests(fetchMock)
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: 'Unban 203.0.113.7' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Type 203.0.113.7 to confirm'), '203.0.113.7')
    await user.click(within(dialog).getByRole('button', { name: en.decisions.unban }))
    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/decisions/10?scope=Ip&value=203.0.113.7')).toHaveLength(1))

    await user.keyboard('{Escape}')
    fireEvent.pointerDown(document.body)
    expect(within(dialog).getByRole('button', { name: en.dialog.cancel })).toBeDisabled()
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    heldResponse.settle(502, { error: 'lapi_unavailable' })
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toHaveTextContent(en.errors.lapi_unavailable)
    expect(within(screen.getByRole('dialog')).getByRole('button', { name: en.dialog.cancel })).toBeEnabled()
  })

  it('banDialogCannotBeClosedWhilePending', async () => {
    const fetchMock = stubFetch(decisionRoutes())
    const heldResponse = holdPostRequests(fetchMock)
    const user = userEvent.setup()
    renderApp('/decisions')

    const dialog = await openBanDialog(user)
    await user.type(within(dialog).getByLabelText(en.ban.ip), '203.0.113.9')
    await user.click(within(dialog).getByRole('button', { name: en.ban.submit }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/decisions')).toHaveLength(1))

    await user.keyboard('{Escape}')
    fireEvent.pointerDown(document.body)
    expect(within(dialog).getByRole('button', { name: en.dialog.cancel })).toBeDisabled()
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    heldResponse.settle(400, { error: 'invalid_target' })
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toHaveTextContent(en.errors.invalid_target)
  })
})
