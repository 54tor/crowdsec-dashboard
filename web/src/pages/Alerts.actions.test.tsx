import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeAlert, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

describe('alert actions', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('deleteAlertSendsOnlyConfirmBodyWithAlertId', async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/alerts?page=1&per_page=20': { status: 200, body: makePage([makeAlert({ id: 42, uuid: 'UUID-42' })]) },
      'GET /api/alerts?page=1&per_page=100': { status: 200, body: makePage([makeAlert({ id: 42, uuid: 'UUID-42' })], { per_page: 100 }) },
      'DELETE /api/alerts/42?uuid=uuid-42': { status: 200, body: { status: 'deleted' } },
    })
    const user = userEvent.setup()
    renderApp('/alerts')

    await user.click(await screen.findByRole('button', { name: 'Delete alert 42' }))
    const dialog = await screen.findByRole('dialog')
    const confirmButton = within(dialog).getByRole('button', { name: en.alerts.delete })
    expect(confirmButton).toBeDisabled()
    await user.type(within(dialog).getByLabelText('Type 42 to confirm'), '42')
    await user.click(confirmButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/alerts/42?uuid=uuid-42')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'DELETE', '/api/alerts/42?uuid=uuid-42')[0].body).toBe('{"confirm":"42"}')
  })

  // Rows of a remote engine, or archived-only rows, share ids with unrelated
  // local alerts: they never offer the live delete action.
  it('offersDeleteOnlyOnLiveLocalRows', async () => {
    const alertRows = [
      makeAlert({ id: 5, engine: 'edge-1', live: false }),
      makeAlert({ id: 6, engine: 'local', live: false }),
      makeAlert({ id: 7, engine: 'local', live: true }),
      makeAlert({ id: 8 }),
    ]
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/alerts?page=1&per_page=20': { status: 200, body: makePage(alertRows) },
      'GET /api/alerts?page=1&per_page=100': { status: 200, body: makePage(alertRows, { per_page: 100 }) },
    })
    renderApp('/alerts')

    expect(await screen.findByRole('button', { name: 'Delete alert 7' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete alert 8' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete alert 5' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete alert 6' })).not.toBeInTheDocument()
  })
})
