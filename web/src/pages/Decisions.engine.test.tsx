import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { makeAlert, makeDecision, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import {
  ENGINE_NAMES_WITH_SIDECARS,
  expectEveryWriteToTarget,
  expectNoEngineParameterAnywhere,
  selectTargetEngine,
  targetEngineNamedIn,
} from '@/test/engineTargetHarness'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

// The alerts page draws a canvas chart that jsdom cannot render.
vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }
const DECISIONS_URL = 'GET /api/decisions?page=1&per_page=20'

// Remote rows come from the archive (live:false); the local row is from the live window.
const LOCAL_DECISION = makeDecision({ id: 10, value: '203.0.113.7' })
// The fixture's default until is already past: remote rows that can still be unbanned need a future one.
const FUTURE_UNTIL = '2099-01-01T00:00:00Z'
const PAST_UNTIL = '2000-01-01T00:00:00Z'
const PEER_DECISION = makeDecision({ id: 20, value: '198.51.100.20', engine: 'peer', live: false, archive_decision_id: 200, until: FUTURE_UNTIL })
const EXPIRED_PEER_DECISION = makeDecision({ id: 21, value: '198.51.100.21', engine: 'peer', live: false, archive_decision_id: 210, until: PAST_UNTIL })
const BARE_DECISION = makeDecision({ id: 30, value: '192.0.2.30', engine: 'bare', live: false, archive_decision_id: 300 })

function decisionEngineRoutes(extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
    [DECISIONS_URL]: { status: 200, body: makePage([LOCAL_DECISION, PEER_DECISION, BARE_DECISION, EXPIRED_PEER_DECISION]) },
    ...extraRoutes,
  }
}

async function openBanDialog(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: en.ban.open }))
  return screen.findByRole('dialog', { name: en.ban.title })
}

async function submitBan(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement, target: string) {
  await user.type(within(dialog).getByLabelText(en.ban.ip), target)
  await user.click(within(dialog).getByRole('button', { name: en.ban.submit }))
}

async function confirmUnban(user: ReturnType<typeof userEvent.setup>, target: string) {
  await user.click(await screen.findByRole('button', { name: `Unban ${target}` }))
  const dialog = await screen.findByRole('dialog')
  const namedEngine = targetEngineNamedIn(dialog)
  await user.type(within(dialog).getByLabelText(`Type ${target} to confirm`), target)
  await user.click(within(dialog).getByRole('button', { name: en.decisions.unban }))
  return namedEngine
}

describe('decisions page engine target', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('bansOnTheSelectedEngine', async () => {
    const fetchMock = stubFetch(decisionEngineRoutes({ 'POST /api/decisions?engine=peer': { status: 201, body: { status: 'created' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    const dialog = await openBanDialog(user)
    await selectTargetEngine(user, 'peer', dialog)
    expect(targetEngineNamedIn(dialog)).toBe('peer')
    await submitBan(user, dialog, '192.0.2.44')

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/decisions?engine=peer')).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/decisions?engine=peer')[0].body))).toEqual({ ip: '192.0.2.44', duration: '24h', reason: '' })
    expect(requestsTo(fetchMock, 'POST', '/api/decisions')).toHaveLength(0)
    expectEveryWriteToTarget(fetchMock, 'peer')
  })

  it('banOnTheLocalEngineSendsNoEngineParameter', async () => {
    const fetchMock = stubFetch(decisionEngineRoutes({ 'POST /api/decisions': { status: 201, body: { status: 'created' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    const dialog = await openBanDialog(user)
    await within(dialog).findByLabelText(en.engineTarget.label)
    expect(targetEngineNamedIn(dialog)).toBe('local')
    await submitBan(user, dialog, '192.0.2.44')

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/decisions')).toHaveLength(1))
    expectNoEngineParameterAnywhere(fetchMock)
  })

  it('rowActionsHiddenForEnginesWithoutSidecar', async () => {
    stubFetch(decisionEngineRoutes())
    renderApp('/decisions')

    await screen.findByRole('button', { name: `Unban ${PEER_DECISION.value}` })

    expect(screen.getByRole('button', { name: `Unban ${LOCAL_DECISION.value}` })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: `Unban ${BARE_DECISION.value}` })).toBeNull()
  })

  // An archived remote row past its until no longer exists on the engine's LAPI:
  // offering Unban would only end in 404 not_found.
  it('expiredRemoteRowOffersNoUnban', async () => {
    stubFetch(decisionEngineRoutes())
    renderApp('/decisions')

    await screen.findByRole('button', { name: `Unban ${PEER_DECISION.value}` })

    expect(screen.getByText(EXPIRED_PEER_DECISION.value)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: `Unban ${EXPIRED_PEER_DECISION.value}` })).toBeNull()
  })

  // Until the engine names arrive, only the local engine is known to be writable.
  it('remoteRowActionsStayHiddenWhileEngineNamesAreUnknown', async () => {
    stubFetch(decisionEngineRoutes({ 'GET /api/engines/names': { status: 503, body: { error: 'database_unavailable' } } }))
    renderApp('/decisions')

    await screen.findByRole('button', { name: `Unban ${LOCAL_DECISION.value}` })

    expect(screen.queryByRole('button', { name: `Unban ${PEER_DECISION.value}` })).toBeNull()
  })

  it('unbansARemoteRowOnItsOwnEngine', async () => {
    const deleteUrl = `/api/decisions/20?scope=Ip&value=198.51.100.20&engine=peer`
    const fetchMock = stubFetch(decisionEngineRoutes({ [`DELETE ${deleteUrl}`]: { status: 200, body: { status: 'deleted' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    const namedEngine = await confirmUnban(user, PEER_DECISION.value)

    expect(namedEngine).toBe('peer')
    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', deleteUrl)).toHaveLength(1))
    expect(requestsTo(fetchMock, 'DELETE', deleteUrl)[0].body).toBe('{"confirm":"20"}')
    expectEveryWriteToTarget(fetchMock, 'peer')
  })

  it('unbansALocalRowWithoutEngineParameter', async () => {
    const deleteUrl = `/api/decisions/10?scope=Ip&value=203.0.113.7`
    const fetchMock = stubFetch(decisionEngineRoutes({ [`DELETE ${deleteUrl}`]: { status: 200, body: { status: 'deleted' } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    const namedEngine = await confirmUnban(user, LOCAL_DECISION.value)

    expect(namedEngine).toBe('local')
    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', deleteUrl)).toHaveLength(1))
    expectNoEngineParameterAnywhere(fetchMock)
  })

  it.each([
    ['engine_has_no_sidecar', 409, en.errors.engine_has_no_sidecar],
    ['engine_target_mismatch', 409, en.errors.engine_target_mismatch],
    ['sidecar_command_refused', 409, en.errors.sidecar_command_refused],
    ['engine_not_found', 404, en.errors.engine_not_found],
    ['sidecar_unavailable', 502, en.errors.sidecar_unavailable],
    ['some_future_code', 409, en.errors.unknown],
  ])('banFailureIsTranslated %s', async (errorCode, status, expectedMessage) => {
    stubFetch(decisionEngineRoutes({ 'POST /api/decisions?engine=peer': { status, body: { error: errorCode } } }))
    const user = userEvent.setup()
    renderApp('/decisions')

    const dialog = await openBanDialog(user)
    await selectTargetEngine(user, 'peer', dialog)
    await submitBan(user, dialog, '192.0.2.44')

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(expectedMessage)
  })

  it('engineErrorCodesExistInBothLanguages', () => {
    const engineErrorCodes = ['engine_has_no_sidecar', 'engine_target_mismatch', 'sidecar_command_refused', 'engine_not_found', 'sidecar_unavailable'] as const
    for (const errorCode of engineErrorCodes) {
      expect(en.errors[errorCode]).toBeTruthy()
      expect(fr.errors[errorCode]).toBeTruthy()
    }
  })

  it('readOnlyAccountSeesNoBanNorRowAction', async () => {
    stubFetch(decisionEngineRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION }))
    renderApp('/decisions')

    await screen.findByText(PEER_DECISION.value)

    expect(screen.queryByRole('button', { name: en.ban.open })).toBeNull()
    expect(screen.queryByRole('button', { name: /^Unban / })).toBeNull()
    expect(screen.queryByLabelText(en.engineTarget.label)).toBeNull()
  })
})

describe('alerts page row engine', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  const PEER_ALERT = makeAlert({ id: 42, uuid: 'UUID-42', engine: 'peer', live: false, archive_id: 420 })
  const BARE_ALERT = makeAlert({ id: 43, uuid: 'UUID-43', engine: 'bare', live: false, archive_id: 430 })

  function alertEngineRoutes(extraRoutes = {}) {
    const alertsPage = makePage([PEER_ALERT, BARE_ALERT])
    return {
      'GET /api/auth/me': SESSION_OK,
      'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
      'GET /api/alerts?page=1&per_page=20': { status: 200, body: alertsPage },
      'GET /api/alerts?page=1&per_page=100': { status: 200, body: { ...alertsPage, per_page: 100 } },
      ...extraRoutes,
    }
  }

  it('deletesARemoteAlertOnItsOwnEngineOnly', async () => {
    const deleteUrl = '/api/alerts/42?uuid=uuid-42&engine=peer'
    const fetchMock = stubFetch(alertEngineRoutes({ [`DELETE ${deleteUrl}`]: { status: 200, body: { status: 'deleted', archive_deleted: true } } }))
    const user = userEvent.setup()
    renderApp('/alerts')

    await user.click(await screen.findByRole('button', { name: en.alerts.deleteAria.replace('{{id}}', '42') }))
    expect(screen.queryByRole('button', { name: en.alerts.deleteAria.replace('{{id}}', '43') })).toBeNull()
    const dialog = await screen.findByRole('dialog')
    expect(targetEngineNamedIn(dialog)).toBe('peer')
    await user.type(within(dialog).getByLabelText('Type 42 to confirm'), '42')
    await user.click(within(dialog).getByRole('button', { name: en.alerts.delete }))

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', deleteUrl)).toHaveLength(1))
    expectEveryWriteToTarget(fetchMock, 'peer')
  })
})
