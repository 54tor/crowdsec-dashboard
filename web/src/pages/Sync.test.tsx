import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { stubFetch } from '@/test/fetchStub'
import { deferredResponse, prepareEnglishApp, requestsTo } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'
import type { SyncPeer, SyncStatus } from '@/api/syncApi'

vi.mock('@/api/syncApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/syncApi')>()),
  SYNC_POLL_INTERVAL_MILLISECONDS: 40,
  SYNC_START_WAIT_MILLISECONDS: 300,
}))

const SYNC_URL = '/api/sync'
const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }
const ROLELESS_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'carol' } }

function makePeer(overrides: Partial<SyncPeer> = {}): SyncPeer {
  return {
    name: 'edge-1', url_host: 'edge-1.example.com:8080', last_run_at: '2026-10-31T10:00:00Z', status: 'ok',
    added: 2, removed: 1, skipped: 0, skipped_allowlisted: 0, blocked_reason: '', error_code: '',
    ...overrides,
  }
}

function makeStatus(overrides: Partial<SyncStatus> = {}): SyncStatus {
  return { enabled: true, dry_run: false, interval_seconds: 300, running: false, error_code: '', peers: [makePeer()], last_plan: [], ...overrides }
}

function syncRoutes(status: SyncStatus, session: { status: number; body: object } = ADMIN_SESSION, extraRoutes = {}) {
  return { 'GET /api/auth/me': session, [`GET ${SYNC_URL}`]: { status: 200, body: status }, ...extraRoutes }
}

describe('sync page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('showsDryRunBanner', async () => {
    stubFetch(syncRoutes(makeStatus({ dry_run: true })))
    renderApp('/sync')
    expect(await screen.findByText(en.sync.dryRun)).toBeInTheDocument()
  })

  it('showsDisabledNotice', async () => {
    stubFetch(syncRoutes(makeStatus({ enabled: false })))
    renderApp('/sync')
    expect(await screen.findByText(en.sync.disabled)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.sync.syncNow })).toBeDisabled()
  })

  // Audit defect 4: the peer status must carry its state colour, and a status
  // the front end does not know yet falls back to the neutral outline badge.
  it.each([
    { peerStatus: 'ok', expectedVariant: 'nominal' },
    { peerStatus: 'blocked', expectedVariant: 'warning' },
    { peerStatus: 'failed', expectedVariant: 'critical' },
    { peerStatus: 'never_run', expectedVariant: 'outline' },
    { peerStatus: 'unknown_future_status', expectedVariant: 'outline' },
  ])('peerStatusBadgeUsesSemanticVariant $peerStatus', async ({ peerStatus, expectedVariant }) => {
    stubFetch(syncRoutes(makeStatus({ peers: [makePeer({ status: peerStatus })] })))
    renderApp('/sync')
    const peerRow = (await screen.findByText('edge-1', { selector: 'bdi' })).closest('tr') as HTMLElement
    const statusBadge = peerRow.querySelector('[data-slot="badge"]') as HTMLElement
    expect(statusBadge).toHaveAttribute('data-variant', expectedVariant)
  })

  it('neverRunPeersShowNeverRun', async () => {
    stubFetch(syncRoutes(makeStatus({ peers: [makePeer({ last_run_at: null, status: 'never_run' })] })))
    renderApp('/sync')
    const row = (await screen.findByText('edge-1', { selector: 'bdi' })).closest('tr') as HTMLElement
    expect(within(row).getAllByText(en.sync.neverRun)).toHaveLength(2)
  })

  it('syncNowDisabledWhileRunning', async () => {
    stubFetch(syncRoutes(makeStatus({ running: true })))
    renderApp('/sync')
    expect(await screen.findByRole('button', { name: en.sync.syncNow })).toBeDisabled()
  })

  it('syncNowHiddenForReadOnly', async () => {
    stubFetch(syncRoutes(makeStatus(), READ_ONLY_SESSION))
    renderApp('/sync')
    await screen.findByText('edge-1', { selector: 'bdi' })
    expect(screen.queryByRole('button', { name: en.sync.syncNow })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: en.sync.manageEngines })).not.toBeInTheDocument()
  })

  it('syncNowHiddenWhenTheRoleIsUnknown', async () => {
    stubFetch(syncRoutes(makeStatus(), ROLELESS_SESSION))
    renderApp('/sync')
    await screen.findByText('edge-1', { selector: 'bdi' })
    expect(screen.queryByRole('button', { name: en.sync.syncNow })).not.toBeInTheDocument()
  })

  it('guardedPeersAreListedAndStayBlockedNotice', async () => {
    const fetchMock = stubFetch(
      syncRoutes(makeStatus({ peers: [makePeer({ status: 'blocked', blocked_reason: 'target_guard' })] }), ADMIN_SESSION, {
        [`POST ${SYNC_URL}/run`]: { status: 202, body: { status: 'started' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/sync')
    const notice = (await screen.findByText(en.sync.guarded)).closest('[role="status"]') as HTMLElement
    expect(within(notice).getByText('edge-1', { selector: 'bdi' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: en.sync.syncNow }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', `${SYNC_URL}/run`)).toHaveLength(1))
  })

  it('rendersPeerNamesAsText', async () => {
    stubFetch(syncRoutes(makeStatus({ peers: [makePeer({ name: '<b>evil</b>' })] })))
    const { container } = renderApp('/sync')
    expect(await screen.findByText('<b>evil</b>', { selector: 'bdi' })).toBeInTheDocument()
    expect(container.querySelector('b')).toBeNull()
  })

  it('rendersAllowlistedSkipReason', async () => {
    stubFetch(syncRoutes(makeStatus({
      peers: [makePeer({ skipped: 3, skipped_allowlisted: 3 })],
      last_plan: [{ engine: 'edge-1', kind: '', target: '203.0.113.7', source: '', reason: 'allowlisted' }],
    })))
    renderApp('/sync')
    expect(await screen.findByText(en.sync.reasons.allowlisted)).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7')).toBeInTheDocument()
  })

  it('rendersAllowlistUnavailableBlock', async () => {
    stubFetch(syncRoutes(makeStatus({ peers: [makePeer({ status: 'blocked', blocked_reason: 'allowlist_unavailable' })] })))
    renderApp('/sync')
    expect(await screen.findByText(en.sync.allowlistUnavailable)).toBeInTheDocument()
    expect(screen.getByText(en.sync.blocked.allowlist_unavailable)).toBeInTheDocument()
  })

  it('keepsUnreachablePeersOutOfTheAllowlistBanner', async () => {
    // A failed read is also reported as allowlist_unavailable by the runner; the error code is the real cause.
    stubFetch(syncRoutes(makeStatus({
      peers: [
        makePeer({ name: 'edge-down', status: 'failed', blocked_reason: 'allowlist_unavailable', error_code: 'engine_unreachable' }),
        makePeer({ name: 'edge-unreadable', status: 'blocked', blocked_reason: 'allowlist_unavailable' }),
      ],
    })))
    renderApp('/sync')
    const banner = (await screen.findByText(en.sync.allowlistUnavailable)).closest('[role="status"]') as HTMLElement
    expect(within(banner).getByText('edge-unreadable', { selector: 'bdi' })).toBeInTheDocument()
    expect(within(banner).queryByText('edge-down', { selector: 'bdi' })).not.toBeInTheDocument()
    const unreachableRow = screen.getByText('edge-down', { selector: 'table bdi' }).closest('tr') as HTMLElement
    expect(within(unreachableRow).getByText(en.sync.errorCodes.engine_unreachable)).toBeInTheDocument()
  })

  it('showsNoAllowlistBannerWhenOnlyUnreachablePeersReportIt', async () => {
    stubFetch(syncRoutes(makeStatus({
      peers: [makePeer({ status: 'failed', blocked_reason: 'allowlist_unavailable', error_code: 'engine_unreachable' })],
    })))
    renderApp('/sync')
    await screen.findByText(en.sync.errorCodes.engine_unreachable)
    expect(screen.queryByText(en.sync.allowlistUnavailable)).not.toBeInTheDocument()
  })

  it('translatesTheRunDeadlineSkipReason', async () => {
    stubFetch(syncRoutes(makeStatus({
      last_plan: [{ engine: 'edge-1', kind: 'add', target: '203.0.113.8', source: 'edge-2', reason: 'run_deadline' }],
    })))
    renderApp('/sync')
    expect(await screen.findByText(en.sync.reasons.run_deadline)).toBeInTheDocument()
    expect(screen.queryByText(en.sync.unknownCode.replace('{{code}}', 'run_deadline'))).not.toBeInTheDocument()
  })

  it('showsTheRunLevelErrorCodeInATopNotice', async () => {
    // The backend also copies the run-level code onto engine rows without a code of their own, hence the scoped lookup.
    stubFetch(syncRoutes(makeStatus({ error_code: 'run_deadline', peers: [makePeer({ error_code: 'run_deadline' })] })))
    renderApp('/sync')
    const notice = (await screen.findByText(en.sync.runErrorTitle)).closest('[role="status"]') as HTMLElement
    expect(within(notice).getByText(en.sync.errorCodes.run_deadline)).toBeInTheDocument()
  })

  it('showsNoRunLevelNoticeWithoutACode', async () => {
    stubFetch(syncRoutes(makeStatus()))
    renderApp('/sync')
    await screen.findByText('edge-1', { selector: 'bdi' })
    expect(screen.queryByText(en.sync.runErrorTitle)).not.toBeInTheDocument()
  })

  it('showsAGenericFallbackForUnknownCodes', async () => {
    stubFetch(syncRoutes(makeStatus({ peers: [makePeer({ error_code: 'brand_new_code' })] })))
    renderApp('/sync')
    expect(await screen.findByText(en.sync.unknownCode.replace('{{code}}', 'brand_new_code'))).toBeInTheDocument()
  })

  it('pollsWhileRunningAndStopsAfter', async () => {
    let statusCallCount = 0
    const fetchMock = stubFetch({
      'GET /api/auth/me': ADMIN_SESSION,
      [`GET ${SYNC_URL}`]: () => {
        statusCallCount += 1
        return { status: 200, body: makeStatus({ running: statusCallCount < 4 }) }
      },
    })
    renderApp('/sync')
    await screen.findByRole('button', { name: en.sync.syncNow })
    await waitFor(() => expect(statusCallCount).toBeGreaterThanOrEqual(4))
    const callsWhenFinished = requestsTo(fetchMock, 'GET', SYNC_URL).length
    await new Promise((resolve) => setTimeout(resolve, 250))
    expect(requestsTo(fetchMock, 'GET', SYNC_URL).length).toBe(callsWhenFinished)
  })

  it('keepsPollingAfterThePostThenStops', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    let isRunStarted = false
    let statusCallsSinceStart = 0
    const fetchMock = stubFetch({
      'GET /api/auth/me': ADMIN_SESSION,
      [`GET ${SYNC_URL}`]: () => {
        statusCallsSinceStart += isRunStarted ? 1 : 0
        return { status: 200, body: makeStatus({ running: statusCallsSinceStart >= 1 && statusCallsSinceStart < 4 }) }
      },
      [`POST ${SYNC_URL}/run`]: () => {
        isRunStarted = true
        return { status: 202, body: { status: 'started' } }
      },
    })
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    renderApp('/sync')
    await user.click(await screen.findByRole('button', { name: en.sync.syncNow }))
    await waitFor(() => expect(statusCallsSinceStart).toBeGreaterThanOrEqual(4))
    await vi.advanceTimersByTimeAsync(1000)
    const callsWhenFinished = requestsTo(fetchMock, 'GET', SYNC_URL).length
    await vi.advanceTimersByTimeAsync(1000)
    expect(requestsTo(fetchMock, 'GET', SYNC_URL).length).toBe(callsWhenFinished)
    vi.useRealTimers()
  })

  it('buttonStaysLockedUntilAPollAfterThePostReturns', async () => {
    const heldPoll = deferredResponse()
    let isRunStarted = false
    const fetchMock = stubFetch({
      'GET /api/auth/me': ADMIN_SESSION,
      [`GET ${SYNC_URL}`]: { status: 200, body: makeStatus() },
      [`POST ${SYNC_URL}/run`]: { status: 202, body: { status: 'started' } },
    })
    const defaultImplementation = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        isRunStarted = true
      }
      return isRunStarted && String(input) === SYNC_URL ? heldPoll.promise : defaultImplementation(input, init)
    })
    const user = userEvent.setup()
    renderApp('/sync')
    const button = await screen.findByRole('button', { name: en.sync.syncNow })
    await user.click(button)
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', `${SYNC_URL}/run`)).toHaveLength(1))
    await new Promise((resolve) => setTimeout(resolve, 100))
    expect(button).toBeDisabled()

    heldPoll.settle(200, makeStatus())
    await waitFor(() => expect(button).toBeEnabled())
  })

  it('doubleClickCannotPostTwice', async () => {
    // Once the POST is served the status reports a running sync, as the real
    // backend does, so the button stays disabled for the whole double click
    // whatever the scheduling under load.
    let hasStarted = false
    const fetchMock = stubFetch({
      ...syncRoutes(makeStatus()),
      [`GET ${SYNC_URL}`]: () => ({ status: 200, body: makeStatus({ running: hasStarted }) }),
      [`POST ${SYNC_URL}/run`]: () => {
        hasStarted = true
        return { status: 202, body: { status: 'started' } }
      },
    })
    const user = userEvent.setup()
    renderApp('/sync')
    await user.dblClick(await screen.findByRole('button', { name: en.sync.syncNow }))
    await new Promise((resolve) => setTimeout(resolve, 100))
    expect(requestsTo(fetchMock, 'POST', `${SYNC_URL}/run`)).toHaveLength(1)
  })

  it('twoClicksInTheSameTickPostOnce', async () => {
    // fireEvent dispatches both clicks before React re-renders, so only a guard set inside the handler can stop the second one.
    const fetchMock = stubFetch(syncRoutes(makeStatus(), ADMIN_SESSION, { [`POST ${SYNC_URL}/run`]: { status: 202, body: { status: 'started' } } }))
    renderApp('/sync')
    const button = await screen.findByRole('button', { name: en.sync.syncNow })
    fireEvent.click(button)
    fireEvent.click(button)
    await new Promise((resolve) => setTimeout(resolve, 100))
    expect(requestsTo(fetchMock, 'POST', `${SYNC_URL}/run`)).toHaveLength(1)
  })

  it.each([
    ['operation_running', en.errors.operation_running],
    ['sync_disabled', en.errors.sync_disabled],
  ])('failingPostShowsErrorAndDoesNotPoll (%s)', async (errorCode, expectedMessage) => {
    const fetchMock = stubFetch(syncRoutes(makeStatus(), ADMIN_SESSION, { [`POST ${SYNC_URL}/run`]: { status: 409, body: { error: errorCode } } }))
    const user = userEvent.setup()
    renderApp('/sync')
    await user.click(await screen.findByRole('button', { name: en.sync.syncNow }))
    expect(await screen.findByText(expectedMessage)).toBeInTheDocument()
    await new Promise((resolve) => setTimeout(resolve, 150))
    expect(requestsTo(fetchMock, 'GET', SYNC_URL).length).toBeLessThanOrEqual(2)
    const callsAfterError = requestsTo(fetchMock, 'GET', SYNC_URL).length
    await new Promise((resolve) => setTimeout(resolve, 150))
    expect(requestsTo(fetchMock, 'GET', SYNC_URL).length).toBe(callsAfterError)
  })

  it('stopsPollingWhenThePageIsUnmounted', async () => {
    const fetchMock = stubFetch(syncRoutes(makeStatus({ running: true })))
    const { unmount } = renderApp('/sync')
    await screen.findByRole('button', { name: en.sync.syncNow })
    unmount()
    const callsAtUnmount = requestsTo(fetchMock, 'GET', SYNC_URL).length
    await new Promise((resolve) => setTimeout(resolve, 200))
    expect(requestsTo(fetchMock, 'GET', SYNC_URL).length).toBe(callsAtUnmount)
  })

  it('translatesEveryServerErrorCode', () => {
    const serverErrorCodes = [
      'operation_running', 'sync_disabled', 'sync_guard_tripped', 'engine_addresses_unknown', 'canceled', 'not_a_copy',
      'engine_failed', 'write_failed', 'run_deadline', 'run_panicked', 'engine_backoff',
      // Per-engine read and write failures reuse engines.ErrorCode (backend/internal/engines/errorcode.go).
      'engine_unreachable', 'engine_auth_failed', 'engine_blocked_address',
      // A participating peer missing from the registry: its copies are kept on the other engines.
      'engine_unavailable',
    ]
    serverErrorCodes.forEach((serverErrorCode) => {
      expect(en.sync.errorCodes).toHaveProperty(serverErrorCode)
      expect(fr.sync.errorCodes).toHaveProperty(serverErrorCode)
    })
    expect(Object.keys(fr.sync.errorCodes).sort()).toEqual(Object.keys(en.sync.errorCodes).sort())
    expect(Object.keys(fr.sync.reasons).sort()).toEqual(Object.keys(en.sync.reasons).sort())
  })
})
