import { screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeBouncer, makeHealth } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { prepareEnglishApp, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const PHONE_VIEWPORT_WIDTH_IN_PIXELS = 390
const ONE_MINUTE_MILLISECONDS = 60_000

async function findBouncerRow(bouncerName: string): Promise<HTMLElement> {
  const table = await screen.findByRole('table', { name: en.health.bouncersCaption })
  return within(table).getByText(bouncerName).closest('tr') as HTMLElement
}

describe('health, metrics, config and hub layout', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('contactStatusOkIsNominal', async () => {
    const recentContact = new Date(Date.now() - ONE_MINUTE_MILLISECONDS).toISOString()
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/bouncers': {
        status: 200,
        body: {
          items: [
            makeBouncer({ name: 'fresh-bouncer', last_pull: recentContact }),
            makeBouncer({ name: 'stale-bouncer', last_pull: '2020-01-01T00:00:00Z' }),
            makeBouncer({ name: 'revoked-bouncer', last_pull: recentContact, revoked: true }),
          ],
        },
      },
    })
    renderApp('/bouncers')

    const freshRow = await findBouncerRow('fresh-bouncer')
    const staleRow = await findBouncerRow('stale-bouncer')
    const revokedRow = await findBouncerRow('revoked-bouncer')

    expect(within(freshRow).getByText(en.health.ok)).toHaveAttribute('data-variant', 'nominal')
    expect(within(staleRow).getByText(en.health.stale)).toHaveAttribute('data-variant', 'warning')
    expect(within(revokedRow).getByText(en.health.revoked)).toHaveAttribute('data-variant', 'critical')
  })

  it('healthSectionUsesPageHeader', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/health': { status: 200, body: makeHealth() },
    })
    renderApp('/bouncers')

    const pageTitle = await screen.findByRole('heading', { level: 1, name: en.bouncers.title })

    expect(pageTitle.tagName).toBe('H1')
    expect(pageTitle).toHaveClass('font-condensed')
    expect(pageTitle.closest('header')).not.toBeNull()
  })

  it('hubEmptyListShowsEmptyState', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/hub': { status: 200, body: [] },
      'GET /api/health': { status: 200, body: makeHealth() },
    })
    renderApp('/hub')

    const emptyMessage = await screen.findByText(en.hub.noItems)

    expect(emptyMessage.parentElement).toHaveClass('border-dashed')
  })

  it('metricsTablesStayTablesOnMobile', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/metrics': {
        status: 200,
        body: {
          available: true,
          acquisition: [{ source: 'file:/var/log/auth.log', lines_read: 636, parsed: 0, unparsed: 636 }],
          parsers: [],
        },
      },
    })
    renderApp('/metrics')

    const table = await screen.findByRole('table', { name: en.metrics.acquisitionCaption })

    expect(table).toBeInTheDocument()
    expect(screen.getAllByRole('region', { name: /acquisition/i })).toHaveLength(1)
  })

  it('configViewerIsMonoOnSurface', async () => {
    stubFetch({
      'GET /api/auth/me': ADMIN_SESSION,
      'GET /api/config/files': { status: 200, body: { files: ['config.yaml'] } },
      'GET /api/config/files/config.yaml': { status: 200, body: { name: 'config.yaml', content: 'api: {}\n' } },
    })
    renderApp('/config')
    const fileButton = await screen.findByRole('button', { name: 'config.yaml' })
    fileButton.click()

    const viewer = await screen.findByLabelText('Content of config.yaml')

    expect(viewer.tagName).toBe('PRE')
    expect(viewer).toHaveClass('font-mono')
    expect(viewer).toHaveClass('bg-secondary')
    expect(viewer.className).not.toContain('ring-ring/50')
  })
})
