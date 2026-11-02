import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }

describe('config page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('configViewerShowsNoCredentialsFile', async () => {
    stubFetch({
      'GET /api/auth/me': ADMIN_SESSION,
      'GET /api/config/files': { status: 200, body: { files: ['config.yaml', 'acquis.d/nginx.yaml'] } },
    })
    renderApp('/config')

    expect(await screen.findByRole('button', { name: 'config.yaml' })).toBeInTheDocument()
    expect(screen.queryByText(/credentials/)).not.toBeInTheDocument()
    expect(screen.getByText(en.config.filesNote)).toBeInTheDocument()
    expect(screen.getByText(en.config.redactionNote)).toBeInTheDocument()
  })

  it('showsSelectedFileContentAsPlainText', async () => {
    const hostileContent = 'api:\n  password: [REDACTED]\n  note: <img src=x onerror=alert(1)>\n'
    stubFetch({
      'GET /api/auth/me': ADMIN_SESSION,
      'GET /api/config/files': { status: 200, body: { files: ['acquis.d/nginx.yaml'] } },
      'GET /api/config/files/acquis.d/nginx.yaml': {
        status: 200,
        body: { name: 'acquis.d/nginx.yaml', content: hostileContent },
      },
    })
    const { container } = renderApp('/config')

    await userEvent.click(await screen.findByRole('button', { name: 'acquis.d/nginx.yaml' }))

    const viewer = await screen.findByLabelText('Content of acquis.d/nginx.yaml')
    expect(viewer.textContent).toBe(hostileContent)
    expect(container.querySelector('img')).toBeNull()
  })

  it('showsTranslatedErrorWhenFileIsTooLarge', async () => {
    stubFetch({
      'GET /api/auth/me': ADMIN_SESSION,
      'GET /api/config/files': { status: 200, body: { files: ['config.yaml'] } },
      'GET /api/config/files/config.yaml': { status: 413, body: { error: 'file_too_large' } },
    })
    renderApp('/config')

    await userEvent.click(await screen.findByRole('button', { name: 'config.yaml' }))

    expect(await screen.findByText(en.errors.file_too_large)).toBeInTheDocument()
  })

  it('redirectsReadOnlyAccountAwayFromConfigAndHidesTheNavEntry', async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/me': READ_ONLY_SESSION,
      'GET /api/alerts?page=1&per_page=20': { status: 200, body: { items: [], total: 0, page: 1, per_page: 20 } },
      'GET /api/alerts?page=1&per_page=100': { status: 200, body: { items: [], total: 0, page: 1, per_page: 100 } },
      'GET /api/config/files': { status: 200, body: { files: ['config.yaml'] } },
    })
    renderApp('/config')

    expect(await screen.findByRole('heading', { name: en.alerts.title })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: en.nav.config })).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([requestedUrl]) => String(requestedUrl).startsWith('/api/config/files'))).toBe(false)
  })
})
