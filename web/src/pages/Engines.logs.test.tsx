import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeEngine } from '@/test/fixtures'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { ENGINE_NAMES_WITH_SIDECARS } from '@/test/engineTargetHarness'
import { INJECTED_IMAGE_SELECTOR, prepareEnglishApp, requestedUrls, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }
const LOCAL_ENGINE = makeEngine({ name: 'local', is_local: true, lapi_url: 'http://crowdsec:8080', machine_id: 'local-machine' })
const NGINX_SOURCE_ID = '0123456789abcdef0123456789abcdef'
const AUTH_SOURCE_ID = 'fedcba9876543210fedcba9876543210'
const LINES_URL = (sourceId: string, engine = '') => `/api/logs/sources/${sourceId}?lines=200${engine}`

const SOURCES_BODY = {
  engine: 'local',
  sources: [
    { id: NGINX_SOURCE_ID, label: '/var/log/nginx/access.log' },
    { id: AUTH_SOURCE_ID, label: '/var/log/auth.log' },
  ],
  unreadable: [{ kind: 'docker', detail: '' }],
  truncated: false,
}

function logRoutes(extraRoutes: RouteTable = {}): RouteTable {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines': { status: 200, body: { items: [LOCAL_ENGINE] } },
    'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
    'GET /api/logs/sources': { status: 200, body: SOURCES_BODY },
    [`GET ${LINES_URL(NGINX_SOURCE_ID)}`]: { status: 200, body: { engine: 'local', source_id: NGINX_SOURCE_ID, lines: ['GET /a 200', 'GET /b 404'], file_size: 20, truncated: false } },
    [`GET ${LINES_URL(AUTH_SOURCE_ID)}`]: { status: 200, body: { engine: 'local', source_id: AUTH_SOURCE_ID, lines: ['sshd accepted'], file_size: 14, truncated: false } },
    ...extraRoutes,
  }
}

describe('engines page received logs', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('afficheLesSourcesEtLesLignesDeLaSourceChoisie', async () => {
    stubFetch(logRoutes())
    const user = userEvent.setup()
    renderApp('/engines')

    await screen.findByText('GET /b 404')
    await user.selectOptions(screen.getByLabelText(en.engineLogs.source), '/var/log/auth.log')

    expect(await screen.findByText('sshd accepted')).toBeInTheDocument()
    expect(screen.queryByText('GET /b 404')).not.toBeInTheDocument()
  })

  it('listeLesSourcesNonFichierCommeNonLisibles', async () => {
    stubFetch(logRoutes())
    renderApp('/engines')

    expect(await screen.findByText(/docker/, { selector: '[data-testid="unreadable-sources"] *' })).toBeInTheDocument()
  })

  it('afficheLEtatDesactiveSurLogsDisabled', async () => {
    stubFetch(logRoutes({ 'GET /api/logs/sources': { status: 409, body: { error: 'logs_disabled' } } }))
    renderApp('/engines')

    expect(await screen.findByText(en.errors.logs_disabled)).toBeInTheDocument()
  })

  it('afficheLEtatSourceDisparueQuandLaLectureRepond404', async () => {
    stubFetch(logRoutes({ [`GET ${LINES_URL(NGINX_SOURCE_ID)}`]: { status: 404, body: { error: 'log_source_not_found' } } }))
    renderApp('/engines')

    expect(await screen.findByText(en.errors.log_source_not_found)).toBeInTheDocument()
  })

  it('lisLesLignesDUnEngineDistantAvecLeParametreEngine', async () => {
    const peerSources = { ...SOURCES_BODY, engine: 'peer', sources: [{ id: NGINX_SOURCE_ID, label: '/srv/peer.log' }], unreadable: [] }
    const fetchMock = stubFetch(
      logRoutes({
        'GET /api/logs/sources?engine=peer': { status: 200, body: peerSources },
        [`GET ${LINES_URL(NGINX_SOURCE_ID, '&engine=peer')}`]: { status: 200, body: { engine: 'peer', source_id: NGINX_SOURCE_ID, lines: ['peer line'], file_size: 9, truncated: false } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/engines')

    await screen.findByText('GET /b 404')
    await user.selectOptions(screen.getByLabelText(en.engineTarget.label), 'peer')

    expect(await screen.findByText('peer line')).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(LINES_URL(NGINX_SOURCE_ID, '&engine=peer'))
  })

  it('neGardePasLesLignesDUnEngineSurUnAutreEngineSansSource', async () => {
    stubFetch(logRoutes({ 'GET /api/logs/sources?engine=peer': { status: 200, body: { engine: 'peer', sources: [], unreadable: [], truncated: false } } }))
    const user = userEvent.setup()
    renderApp('/engines')

    await screen.findByText('GET /b 404')
    await user.selectOptions(screen.getByLabelText(en.engineTarget.label), 'peer')

    await screen.findByText(en.engineLogs.noSources)
    expect(screen.queryByText('GET /b 404')).not.toBeInTheDocument()
  })

  it('neRendJamaisLeContenuDUneLigneCommeHtml', async () => {
    stubFetch(logRoutes({ [`GET ${LINES_URL(NGINX_SOURCE_ID)}`]: { status: 200, body: { engine: 'local', source_id: NGINX_SOURCE_ID, lines: ['<img src=x onerror=alert(1)>'], file_size: 1, truncated: false } } }))
    renderApp('/engines')

    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(document.querySelector(INJECTED_IMAGE_SELECTOR)).toBeNull()
  })

  it('redirigeUnLecteurSansAppelerLApiDesLogs', async () => {
    const fetchMock = stubFetch(logRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION, 'GET /api/alerts': { status: 200, body: { items: [], total: 0 } } }))
    const { visitedPaths } = renderApp('/engines')

    await waitFor(() => expect(visitedPaths[visitedPaths.length - 1]).toBe('/alerts'))

    expect(requestedUrls(fetchMock).filter((requestedUrl) => requestedUrl.startsWith('/api/logs'))).toEqual([])
  })

  it('affichePlusieursLignesDansUnBlocEnLectureSeule', async () => {
    stubFetch(logRoutes())
    renderApp('/engines')

    const linesBlock = await screen.findByRole('log', { name: en.engineLogs.linesLabel })

    await waitFor(() => expect(within(linesBlock).getByText('GET /a 200')).toBeInTheDocument())
  })
})
