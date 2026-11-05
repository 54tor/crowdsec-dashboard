import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { stubFetch } from '@/test/fetchStub'
import { ENGINE_NAMES_WITH_SIDECARS, holdRequestsTo, offeredEngineNames, selectTargetEngine, targetEngineNamedIn } from '@/test/engineTargetHarness'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const LOCAL_CONTENT = 'api:\n  server:\n    listen_uri: 127.0.0.1:8080\n'
const PEER_CONTENT = 'source: file\npassword: [REDACTED]\n'

function configEngineRoutes(extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
    'GET /api/config/files': { status: 200, body: { files: ['config.yaml'] } },
    'GET /api/config/files/config.yaml': { status: 200, body: { name: 'config.yaml', content: LOCAL_CONTENT } },
    'GET /api/config/files?engine=peer': { status: 200, body: { files: ['acquis.yaml'] } },
    'GET /api/config/files/acquis.yaml?engine=peer': { status: 200, body: { name: 'acquis.yaml', content: PEER_CONTENT } },
    ...extraRoutes,
  }
}

describe('config page engine target', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('offersTheLocalEngineAndTheEnginesWithASidecar', async () => {
    stubFetch(configEngineRoutes())
    renderApp('/config')

    await screen.findByLabelText(en.engineTarget.label)

    expect(offeredEngineNames()).toEqual(['local', 'peer'])
  })

  it('readsTheConfigOfTheSelectedEngine', async () => {
    const fetchMock = stubFetch(configEngineRoutes())
    const user = userEvent.setup()
    renderApp('/config')
    await screen.findByRole('button', { name: 'config.yaml' })

    await selectTargetEngine(user, 'peer')
    await user.click(await screen.findByRole('button', { name: 'acquis.yaml' }))

    const viewer = await screen.findByLabelText('Content of acquis.yaml')
    expect(viewer.textContent).toBe(PEER_CONTENT)
    expect(targetEngineNamedIn(viewer.parentElement as HTMLElement)).toBe('peer')
    expect(screen.queryByRole('button', { name: 'config.yaml' })).toBeNull()
    expect(requestsTo(fetchMock, 'GET', '/api/config/files?engine=peer')).toHaveLength(1)
    expect(requestsTo(fetchMock, 'GET', '/api/config/files/acquis.yaml?engine=peer')).toHaveLength(1)
    expect(requestsTo(fetchMock, 'GET', '/api/config/files/acquis.yaml')).toHaveLength(0)
  })

  it('namesTheLocalEngineNextToALocalFile', async () => {
    stubFetch(configEngineRoutes())
    const user = userEvent.setup()
    renderApp('/config')

    await user.click(await screen.findByRole('button', { name: 'config.yaml' }))

    const viewer = await screen.findByLabelText('Content of config.yaml')
    expect(targetEngineNamedIn(viewer.parentElement as HTMLElement)).toBe('local')
  })

  // While the peer's list is in flight nothing of the local engine may stay on
  // screen, and the file picked on local must not be asked of the peer.
  it('switchingEngineNeverShowsThePreviousEnginesFilesOrContent', async () => {
    const fetchMock = stubFetch(configEngineRoutes())
    const user = userEvent.setup()
    renderApp('/config')
    await user.click(await screen.findByRole('button', { name: 'config.yaml' }))
    await screen.findByLabelText('Content of config.yaml')
    const heldPeerList = holdRequestsTo(fetchMock, '/api/config/files?engine=peer')

    await selectTargetEngine(user, 'peer')

    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/config/files?engine=peer')).toHaveLength(1))
    expect(screen.queryByRole('button', { name: 'config.yaml' })).toBeNull()
    expect(screen.queryByLabelText('Content of config.yaml')).toBeNull()
    expect(screen.queryByText(/listen_uri/)).toBeNull()

    heldPeerList.settle(200, { files: ['acquis.yaml'] })
    expect(await screen.findByRole('button', { name: 'acquis.yaml' })).toBeInTheDocument()
    expect(screen.getByText(en.config.select)).toBeInTheDocument()
    expect(requestsTo(fetchMock, 'GET', '/api/config/files/config.yaml?engine=peer')).toHaveLength(0)
  })

  it('selectedFileResetsWhenTheEngineChangesBack', async () => {
    stubFetch(configEngineRoutes())
    const user = userEvent.setup()
    renderApp('/config')
    await selectTargetEngine(user, 'peer')
    await user.click(await screen.findByRole('button', { name: 'acquis.yaml' }))
    await screen.findByLabelText('Content of acquis.yaml')

    await selectTargetEngine(user, 'local')

    expect(await screen.findByRole('button', { name: 'config.yaml' })).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByText(en.config.select)).toBeInTheDocument()
    expect(screen.queryByLabelText('Content of acquis.yaml')).toBeNull()
  })

  it('showsTheTranslatedErrorOfTheSelectedEngine', async () => {
    stubFetch(configEngineRoutes({ 'GET /api/config/files?engine=peer': { status: 502, body: { error: 'sidecar_unavailable' } } }))
    const user = userEvent.setup()
    renderApp('/config')
    await screen.findByRole('button', { name: 'config.yaml' })

    await selectTargetEngine(user, 'peer')

    expect(await screen.findByText(en.errors.sidecar_unavailable)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'config.yaml' })).toBeNull()
  })
})
