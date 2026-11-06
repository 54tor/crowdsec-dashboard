import { screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { makeEngine } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { ENGINE_NAMES_WITH_SIDECARS } from '@/test/engineTargetHarness'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/lib/logPolling', () => ({ LOG_POLL_INTERVAL_MILLISECONDS: 60, LOG_LINES_REQUESTED: 200 }))

const SOURCE_ID = '0123456789abcdef0123456789abcdef'
const LINES_URL = `/api/logs/sources/${SOURCE_ID}?lines=200`

function pollingRoutes() {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines': { status: 200, body: { items: [makeEngine({ name: 'local', is_local: true })] } },
    'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
    'GET /api/logs/sources': { status: 200, body: { engine: 'local', sources: [{ id: SOURCE_ID, label: '/var/log/app.log' }], unreadable: [], truncated: false } },
    [`GET ${LINES_URL}`]: { status: 200, body: { engine: 'local', source_id: SOURCE_ID, lines: ['tick'], file_size: 4, truncated: false } },
  }
}

describe('engines page received logs polling', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('rafraichitLesLignesALIntervalleConfigure', async () => {
    const fetchMock = stubFetch(pollingRoutes())
    renderApp('/engines')

    await screen.findByText('tick')

    await waitFor(() => expect(requestsTo(fetchMock, 'GET', LINES_URL).length).toBeGreaterThanOrEqual(3))
  })

  it('suspendLePollingQuandLOngletEstCache', async () => {
    const fetchMock = stubFetch(pollingRoutes())
    renderApp('/engines')
    await screen.findByText('tick')

    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    const requestsBeforePause = requestsTo(fetchMock, 'GET', LINES_URL).length
    await new Promise((resolve) => setTimeout(resolve, 300))

    expect(requestsTo(fetchMock, 'GET', LINES_URL).length).toBeLessThanOrEqual(requestsBeforePause + 1)
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' })
  })
})
