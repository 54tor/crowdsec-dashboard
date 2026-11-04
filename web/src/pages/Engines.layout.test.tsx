import { screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { SyncStatus } from '@/api/syncApi'
import en from '@/i18n/en.json'
import { makeEngine } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { prepareEnglishApp } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const PHONE_VIEWPORT_WIDTH_IN_PIXELS = 390
const SYNC_STATUS: SyncStatus = { enabled: true, dry_run: false, interval_seconds: 300, running: false, error_code: '', peers: [], last_plan: [] }

function stubEngines(engineRows = [makeEngine()]) {
  return stubFetch({
    'GET /api/auth/me': ADMIN_SESSION,
    'GET /api/engines': { status: 200, body: { items: engineRows } },
    'GET /api/sync': { status: 200, body: SYNC_STATUS },
  })
}

async function findEngineRow(): Promise<HTMLElement> {
  const table = await screen.findByRole('table', { name: en.engines.caption })
  return within(table).getByText('remote-one').closest('tr') as HTMLElement
}

describe('engines page layout', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('engineStateBadgesUseStateVariants', async () => {
    stubEngines([
      makeEngine({ name: 'remote-one', enabled: true, sync_enabled: true }),
      makeEngine({ name: 'remote-two', enabled: false, is_local: true }),
    ])
    renderApp('/engines')

    const enabledRow = await findEngineRow()
    const disabledRow = (await screen.findByText('remote-two')).closest('tr') as HTMLElement

    expect(within(enabledRow).getByText(en.engines.enabled)).toHaveAttribute('data-variant', 'nominal')
    expect(within(enabledRow).getByText(en.engines.syncEnabled)).toHaveAttribute('data-variant', 'info')
    expect(within(disabledRow).getByText(en.engines.disabled)).toHaveAttribute('data-variant', 'outline')
    expect(within(disabledRow).getByText(en.engines.local)).toHaveAttribute('data-variant', 'neutral')
  })

  it('collectionErrorIsCritical', async () => {
    const engineWithError = makeEngine({
      collection: { ...makeEngine().collection, last_error_code: 'engine_secret_unreadable' },
    })
    stubEngines([engineWithError])
    renderApp('/engines')

    const engineRow = await findEngineRow()

    expect(engineRow.querySelector('.text-critical')).not.toBeNull()
    expect(engineRow.querySelector('.text-destructive')).toBeNull()
  })

  it('emptyEngineListShowsEmptyState', async () => {
    stubEngines([])
    renderApp('/engines')

    expect(await screen.findByText(en.engines.empty)).toBeInTheDocument()
  })

  it('engineCardsOnMobile', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubEngines()
    renderApp('/engines')

    const cardList = await screen.findByRole('list', { name: en.engines.caption })
    const [engineCard] = within(cardList).getAllByRole('listitem')

    expect(within(engineCard).getByText('remote-one')).toBeInTheDocument()
    expect(within(engineCard).getByText('https://lapi.example.com:8080')).toHaveClass('font-mono')
    expect(within(engineCard).getByRole('button', { name: 'Edit remote-one' })).toBeInTheDocument()
  })

  it('enginesPageHeaderHoldsTheAddAction', async () => {
    stubEngines()
    renderApp('/engines')

    const pageTitle = await screen.findByRole('heading', { level: 1, name: en.engines.title })
    const pageHeader = pageTitle.closest('header') as HTMLElement

    expect(within(pageHeader).getByRole('button', { name: en.engines.add })).toBeInTheDocument()
  })
})

describe('sync and export pages layout', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('syncAndExportUsePageHeader', async () => {
    stubEngines()
    const pageTitles = [
      { path: '/sync', title: en.sync.title },
      { path: '/export-import', title: en.bundle.title },
    ]
    for (const pageTitleCase of pageTitles) {
      const { unmount } = renderApp(pageTitleCase.path)

      const pageTitle = await screen.findByRole('heading', { level: 1, name: pageTitleCase.title })

      expect(pageTitle.closest('header')).not.toBeNull()
      expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
      unmount()
    }
  })

  it('exportAndImportPanelsAreBorderedCards', async () => {
    stubEngines()
    renderApp('/export-import')

    const exportPanel = (await screen.findByRole('heading', { name: en.bundle.exportTitle })).closest('section') as HTMLElement
    const importPanel = screen.getByRole('heading', { name: en.bundle.importTitle }).closest('section') as HTMLElement

    expect(exportPanel).toHaveClass('bg-card', 'border', 'rounded-md', 'p-4')
    expect(importPanel).toHaveClass('bg-card', 'border', 'rounded-md', 'p-4')
  })
})
