import { screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeHealth } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ONE_MINUTE_MILLISECONDS = 60_000

function machine(machineId: string, lastHeartbeat: string | null) {
  return {
    machine_id: machineId,
    ip_address: '203.0.113.20',
    last_heartbeat: lastHeartbeat,
    version: 'v1.7.3',
    is_validated: true,
    auth_type: 'password',
    self: false,
  }
}

function bouncer(name: string, lastPull: string | null, revoked = false) {
  return {
    name,
    type: 'crowdsec-firewall-bouncer',
    version: 'v0.0.31',
    ip_address: '203.0.113.30',
    last_pull: lastPull,
    revoked,
    auth_type: 'api-key',
  }
}

describe('health page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('healthFlagsStaleMachine', async () => {
    const recentHeartbeat = new Date(Date.now() - ONE_MINUTE_MILLISECONDS).toISOString()
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': {
        status: 200,
        body: makeHealth({
          machines: [machine('fresh-machine', recentHeartbeat), machine('stale-machine', '2020-01-01T00:00:00Z')],
        }),
      },
    })
    renderApp('/health')

    const staleRow = (await screen.findByText('stale-machine')).closest('tr') as HTMLElement
    const freshRow = screen.getByText('fresh-machine').closest('tr') as HTMLElement
    expect(within(staleRow).getByText(en.health.stale)).toBeInTheDocument()
    expect(within(freshRow).queryByText(en.health.stale)).not.toBeInTheDocument()
    expect(within(freshRow).getByText(en.health.ok)).toBeInTheDocument()
  })

  it('marksTheDashboardOwnMachineWithoutStaleOrNeverWording', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': {
        status: 200,
        body: makeHealth({ machines: [{ ...machine('dashboard-machine', null), self: true }, machine('other-machine', '2020-01-01T00:00:00Z')] }),
      },
    })
    renderApp('/health')

    const selfRow = (await screen.findByText('dashboard-machine')).closest('tr') as HTMLElement
    const otherRow = screen.getByText('other-machine').closest('tr') as HTMLElement
    expect(within(selfRow).getByText(en.health.self)).toBeInTheDocument()
    expect(within(selfRow).queryByText(en.health.stale)).not.toBeInTheDocument()
    expect(within(selfRow).queryByText(en.health.never)).not.toBeInTheDocument()
    expect(within(selfRow).queryByText(en.health.ok)).not.toBeInTheDocument()
    expect(within(selfRow).getByText(en.health.validated)).toBeInTheDocument()
    expect(within(otherRow).queryByText(en.health.self)).not.toBeInTheDocument()
    expect(within(otherRow).getByText(en.health.stale)).toBeInTheDocument()
  })

  it('showsVersionAndMarksRevokedBouncer', async () => {
    const recentPull = new Date(Date.now() - ONE_MINUTE_MILLISECONDS).toISOString()
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': {
        status: 200,
        body: makeHealth({ bouncers: [bouncer('revoked-bouncer', recentPull, true), bouncer('never-pulled', null)] }),
      },
    })
    renderApp('/health')

    const revokedRow = (await screen.findByText('revoked-bouncer')).closest('tr') as HTMLElement
    expect(within(revokedRow).getByText(en.health.revoked)).toBeInTheDocument()
    expect(screen.getByText('v1.7.3')).toBeInTheDocument()
    const neverRow = screen.getByText('never-pulled').closest('tr') as HTMLElement
    expect(within(neverRow).getByText(en.health.never)).toBeInTheDocument()
  })

  it('showsOneTranslatedWarningPerDegradedPart', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': { status: 200, body: makeHealth({ degraded: ['bouncers', 'machines'] }) },
    })
    renderApp('/health')

    expect(await screen.findByText(en.health.degraded.bouncers)).toBeInTheDocument()
    expect(screen.getByText(en.health.degraded.machines)).toBeInTheDocument()
    expect(screen.queryByText(en.health.degraded.version)).not.toBeInTheDocument()
  })

  it('rendersMachineNamesAsText', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': { status: 200, body: makeHealth({ machines: [machine('<img src=x onerror=alert(1)>', null)] }) },
    })
    const { container } = renderApp('/health')

    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
  })

  it('showsDatabaseUnavailable', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': { status: 200, body: makeHealth({ database: 'unavailable' }) },
    })
    renderApp('/health')

    expect(await screen.findByText(en.health.database.unavailable)).toBeInTheDocument()
  })

  it('showsSchemaVersionWhenPresent', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': { status: 200, body: makeHealth({ schema_version: 7 }) },
    })
    renderApp('/health')

    expect(await screen.findByText(en.health.database.ok)).toBeInTheDocument()
    expect(screen.getByText(/Schema version/)).toHaveTextContent('7')
  })

  it('listsEachEngineWithLastCollectionAndLag', async () => {
    const recentSuccess = new Date(Date.now() - ONE_MINUTE_MILLISECONDS).toISOString()
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': {
        status: 200,
        body: makeHealth({
          collector: [{ engine_name: 'alerts-engine', last_success_at: recentSuccess, lag_seconds: 42, errors_total: 3, stale: false }],
        }),
      },
    })
    renderApp('/health')

    const engineRow = (await screen.findByText('alerts-engine')).closest('tr') as HTMLElement
    expect(within(engineRow).getByText('42 s')).toBeInTheDocument()
    expect(within(engineRow).getByText('3')).toBeInTheDocument()
    expect(within(engineRow).queryByText(en.health.collector.stale)).not.toBeInTheDocument()
  })

  it('flagsStaleEngine', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': {
        status: 200,
        body: makeHealth({
          collector: [{ engine_name: 'late-engine', last_success_at: '2020-01-01T00:00:00Z', lag_seconds: 900, errors_total: 0, stale: true }],
        }),
      },
    })
    renderApp('/health')

    const engineRow = (await screen.findByText('late-engine')).closest('tr') as HTMLElement
    expect(within(engineRow).getByText(en.health.collector.stale)).toBeInTheDocument()
  })

  it('showsNeverSinceStartupWhenNoSuccess', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': {
        status: 200,
        body: makeHealth({
          collector: [{ engine_name: 'silent-engine', last_success_at: null, lag_seconds: null, errors_total: 1, stale: true }],
        }),
      },
    })
    renderApp('/health')

    const engineRow = (await screen.findByText('silent-engine')).closest('tr') as HTMLElement
    expect(within(engineRow).getByText(en.health.collector.neverSinceStartup)).toBeInTheDocument()
  })

  it('rendersEngineNameAsPlainText', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': {
        status: 200,
        body: makeHealth({
          collector: [{ engine_name: 'engine-<b>bold</b>', last_success_at: null, lag_seconds: null, errors_total: 0, stale: false }],
        }),
      },
    })
    const { container } = renderApp('/health')

    expect(await screen.findByText('engine-<b>bold</b>')).toBeInTheDocument()
    expect(container.querySelector('b')).toBeNull()
  })
})
