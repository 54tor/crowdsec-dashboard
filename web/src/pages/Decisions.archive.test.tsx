import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { BIDI_OVERRIDE_SAMPLE, makeDecision, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestedUrls, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const DECISIONS_URL = '/api/decisions?page=1&per_page=20'
const EXPIRED_DECISIONS_URL = '/api/decisions?page=1&per_page=20&include_expired=true'

describe('decisions page with archive', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  // Archived decisions carry their until as known at collection time: they are
  // never presented as enforced and never offer an unban.
  it('marque les décisions archivées comme non actives', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${DECISIONS_URL}`]: {
        status: 200,
        body: makePage([makeDecision({ id: 10, value: '198.51.100.9', engine: 'edge-1', live: false, duration: '' }), makeDecision({ id: 11, value: '203.0.113.8' })]),
      },
    })
    renderApp('/decisions')

    const archivedRow = (await screen.findByText('198.51.100.9')).closest('tr')!
    expect(within(archivedRow).getByText(en.decisions.archivedBadge)).toBeInTheDocument()
    expect(within(archivedRow).getByText('edge-1')).toBeInTheDocument()
    expect(within(archivedRow).queryByRole('button', { name: /Unban/ })).not.toBeInTheDocument()
    const liveRow = screen.getByText('203.0.113.8').closest('tr')!
    expect(within(liveRow).queryByText(en.decisions.archivedBadge)).not.toBeInTheDocument()
    expect(within(liveRow).getByRole('button', { name: 'Unban 203.0.113.8' })).toBeInTheDocument()
  })

  it('affiche les décisions expirées sur demande', async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${DECISIONS_URL}`]: { status: 200, body: makePage([makeDecision()]) },
      [`GET ${EXPIRED_DECISIONS_URL}`]: {
        status: 200,
        body: makePage([makeDecision({ id: 12, value: '198.51.100.44', live: false, until: '2026-01-01T00:00:00Z', duration: '' })]),
      },
    })
    const user = userEvent.setup()
    renderApp('/decisions')
    await screen.findByText('203.0.113.7', { selector: 'td bdi' })

    expect(screen.getByRole('table', { name: en.decisions.caption })).toBeInTheDocument()

    await user.click(screen.getByLabelText(en.decisions.includeExpired))

    expect(await screen.findByText('198.51.100.44')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(EXPIRED_DECISIONS_URL)
    expect(screen.getByRole('table', { name: en.decisions.captionWithExpired })).toBeInTheDocument()
  })

  it("revient à la première page quand on affiche les décisions expirées", async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${DECISIONS_URL}`]: { status: 200, body: makePage([makeDecision()], { total: 45 }) },
      'GET /api/decisions?page=2&per_page=20': { status: 200, body: makePage([makeDecision({ id: 30, value: '203.0.113.30' })], { page: 2, total: 45 }) },
      [`GET ${EXPIRED_DECISIONS_URL}`]: { status: 200, body: makePage([makeDecision({ id: 31, value: '198.51.100.31', live: false, duration: '' })], { total: 45 }) },
    })
    const user = userEvent.setup()
    renderApp('/decisions')
    await screen.findByText('203.0.113.7', { selector: 'td bdi' })
    await user.click(screen.getByRole('button', { name: en.list.next }))
    expect(await screen.findByText('Page 2 of 3')).toBeInTheDocument()

    await user.click(screen.getByLabelText(en.decisions.includeExpired))

    expect(await screen.findByText('198.51.100.31')).toBeInTheDocument()
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(EXPIRED_DECISIONS_URL)
    expect(requestedUrls(fetchMock)).not.toContain('/api/decisions?page=2&per_page=20&include_expired=true')
  })

  // A live decision and an archived one can share engine and upstream id.
  it('keepsLiveAndArchivedDecisionsSharingAnId', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${DECISIONS_URL}`]: {
        status: 200,
        body: makePage([
          makeDecision({ id: 20, value: '203.0.113.20' }),
          makeDecision({ id: 20, value: '203.0.113.21', live: false, archive_decision_id: 5 }),
          makeDecision({ id: 20, value: '203.0.113.22', engine: 'edge-1', live: false, archive_decision_id: 6 }),
        ]),
      },
    })
    renderApp('/decisions')

    expect(await screen.findByText('203.0.113.22')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.21')).toBeInTheDocument()
    const duplicateKeyWarnings = consoleErrorSpy.mock.calls.filter((loggedArguments) => String(loggedArguments[0]).includes('same key'))
    expect(duplicateKeyWarnings).toHaveLength(0)
    consoleErrorSpy.mockRestore()
  })

  // A reset of the local engine database reuses upstream ids: two archived
  // generations of decision 10 share engine, id and live flag, and only their
  // archive id tells them apart.
  it("ligne de décision : la clé est l'id d'archive", async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${DECISIONS_URL}`]: {
        status: 200,
        body: makePage([
          makeDecision({ id: 10, value: '203.0.113.30', live: false, archive_decision_id: 41 }),
          makeDecision({ id: 10, value: '203.0.113.31', live: false, archive_decision_id: 42 }),
        ]),
      },
    })
    renderApp('/decisions')

    expect(await screen.findByText('203.0.113.30')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.31')).toBeInTheDocument()
    const duplicateKeyWarnings = consoleErrorSpy.mock.calls.filter((loggedArguments) => String(loggedArguments[0]).includes('same key'))
    expect(duplicateKeyWarnings).toHaveLength(0)
    consoleErrorSpy.mockRestore()
  })

  it('isolatesBidiOverrideInDecisionValue', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${DECISIONS_URL}`]: { status: 200, body: makePage([makeDecision({ value: BIDI_OVERRIDE_SAMPLE, scenario: BIDI_OVERRIDE_SAMPLE })]) },
    })
    renderApp('/decisions')

    const table = await screen.findByRole('table', { name: en.decisions.caption })
    const isolatedCells = Array.from(table.querySelectorAll('bdi')).filter((isolatedText) => isolatedText.textContent === BIDI_OVERRIDE_SAMPLE)
    expect(isolatedCells).toHaveLength(2)
  })
})
