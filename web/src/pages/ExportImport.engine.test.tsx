import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ImportPlan } from '@/api/bundleApi'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { stubFetch } from '@/test/fetchStub'
import { ENGINE_NAMES_WITH_SIDECARS, engineParametersOf, expectNoEngineParameterAnywhere, selectTargetEngine, targetEngineNamedIn } from '@/test/engineTargetHarness'
import { holdPostRequests, prepareEnglishApp, requestedUrls, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const PAGE_PATH = '/export-import'
const BUNDLE_CONTENT = { format: 'crowdsec-dashboard-bundle', version: 1, sections: { hub: { collections: [] } } }
const EXPORT_HEADERS = { 'Content-Disposition': 'attachment; filename="crowdsec-bundle-2026-11-05.json"', 'X-Bundle-Skipped-Alerts': '0' }
const APPLIED_REPORT = { digest: 'digest-peer', report: { sections: [{ section: 'hub', status: 'applied', applied: 1, skipped: 0, failed: 0, skipped_reasons: {} }] } }

function makePlan(digest: string): ImportPlan {
  return {
    sections: ['hub'],
    hub: [{ name: 'crowdsecurity/linux', version: '1.0' }],
    decisions: [],
    alerts: [],
    config: [],
    skipped: [],
    skipped_counts: {},
    warnings: [],
    unavailable: [],
    unavailable_codes: {},
    digest,
  }
}

function engineRoutes(extraRoutes = {}) {
  return { 'GET /api/auth/me': SESSION_OK, 'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS, ...extraRoutes }
}

// Each panel has its own "Target engine" selector, so every lookup is scoped to its region.
function exportPanel(): HTMLElement {
  return screen.getByRole('region', { name: en.bundle.exportTitle })
}

function importPanel(): HTMLElement {
  return screen.getByRole('region', { name: en.bundle.importTitle })
}

async function waitForPanels() {
  await screen.findByRole('region', { name: en.bundle.importTitle })
  await within(exportPanel()).findByLabelText(en.engineTarget.label)
  await within(importPanel()).findByLabelText(en.engineTarget.label)
}

async function uploadAndPreview(user: ReturnType<typeof userEvent.setup>) {
  const bundleFile = new File([JSON.stringify(BUNDLE_CONTENT)], 'bundle.json', { type: 'application/json' })
  await user.upload(within(importPanel()).getByLabelText(en.bundle.fileLabel), bundleFile)
  await user.click(await within(importPanel()).findByRole('button', { name: en.bundle.previewButton }))
}

async function applyWithTypedConfirmation(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await within(importPanel()).findByRole('button', { name: en.bundle.applyButton }))
  const dialog = await screen.findByRole('dialog')
  await user.type(within(dialog).getByLabelText(en.bundle.typeToConfirm.replace('{{word}}', 'IMPORT')), 'IMPORT')
  await user.click(within(dialog).getByRole('button', { name: en.bundle.applyButton }))
  return dialog
}

function importRequestUrls(fetchMock: { mock: { calls: unknown[][] } }): string[] {
  return requestedUrls(fetchMock).filter((requestedUrl) => requestedUrl.startsWith('/api/import'))
}

function stubDownload() {
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: () => 'blob:fake', revokeObjectURL: vi.fn() }))
}

describe('export and import page engine target', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('exportsFromTheSelectedEngine', async () => {
    stubDownload()
    const fetchMock = stubFetch(engineRoutes({ 'POST /api/export?engine=peer': { status: 200, body: { ok: true }, headers: EXPORT_HEADERS } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()

    await selectTargetEngine(user, 'peer', exportPanel())
    expect(targetEngineNamedIn(exportPanel())).toBe('peer')
    await user.click(within(exportPanel()).getByRole('button', { name: en.bundle.exportButton }))

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/export?engine=peer')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'POST', '/api/export')).toHaveLength(0)
    const exportUrls = requestedUrls(fetchMock).filter((requestedUrl) => requestedUrl.startsWith('/api/export'))
    expect(exportUrls.map(engineParametersOf)).toEqual([['peer']])
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/export?engine=peer')[0].body))).toMatchObject({ include_secrets: false, confirm_secrets: '' })
  })

  it('previewIsResetWhenTheEngineChanges', async () => {
    const fetchMock = stubFetch(engineRoutes({ 'POST /api/import': { status: 200, body: makePlan('digest-local') } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()
    await uploadAndPreview(user)
    expect(await screen.findByRole('table', { name: en.bundle.summaryCaption })).toBeInTheDocument()

    await selectTargetEngine(user, 'peer', importPanel())

    expect(screen.queryByRole('table', { name: en.bundle.summaryCaption })).toBeNull()
    expect(within(importPanel()).queryByRole('button', { name: en.bundle.applyButton })).toBeNull()
    expect(screen.queryByText('crowdsecurity/linux 1.0')).toBeNull()
    // The loaded file is kept: only the preview made for the local engine is discarded.
    expect(within(importPanel()).getByRole('button', { name: en.bundle.previewButton })).toBeEnabled()
    expect(importRequestUrls(fetchMock)).toEqual(['/api/import'])
  })

  it('applyCarriesTheSameEngineAsThePreview', async () => {
    let importCallCount = 0
    const fetchMock = stubFetch(
      engineRoutes({ 'POST /api/import?engine=peer': () => ({ status: 200, body: ++importCallCount === 1 ? makePlan('digest-peer') : APPLIED_REPORT }) }),
    )
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()
    await selectTargetEngine(user, 'peer', importPanel())
    await uploadAndPreview(user)
    await screen.findByRole('table', { name: en.bundle.summaryCaption })

    const dialog = await applyWithTypedConfirmation(user)
    expect(targetEngineNamedIn(dialog)).toBe('peer')

    const report = await screen.findByRole('status')
    expect(within(report).getByText(en.bundle.resultTitle)).toBeInTheDocument()
    expect(targetEngineNamedIn(report)).toBe('peer')
    expect(importRequestUrls(fetchMock).map(engineParametersOf)).toEqual([['peer'], ['peer']])
    const [previewBody, applyBody] = requestsTo(fetchMock, 'POST', '/api/import?engine=peer').map((request) => JSON.parse(String(request.body)))
    expect(previewBody.mode).toBe('preview')
    expect(applyBody).toMatchObject({ mode: 'apply', digest: 'digest-peer', confirm: 'IMPORT' })
  })

  it('secretsOptionIsDisabledForARemoteEngineAndResetOnReturnToLocal', async () => {
    stubDownload()
    const fetchMock = stubFetch(engineRoutes({ 'POST /api/export': { status: 200, body: { ok: true }, headers: EXPORT_HEADERS } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()
    const secretsOption = within(exportPanel()).getByLabelText(en.bundle.includeSecrets)
    await user.click(secretsOption)
    expect(within(exportPanel()).getByText(en.bundle.secretsWarning)).toBeInTheDocument()

    await selectTargetEngine(user, 'peer', exportPanel())

    expect(secretsOption).toBeDisabled()
    expect(secretsOption).not.toBeChecked()
    expect(within(exportPanel()).getByText(en.bundle.secretsRemoteUnavailable)).toBeInTheDocument()
    expect(within(exportPanel()).queryByText(en.bundle.secretsWarning)).toBeNull()

    await selectTargetEngine(user, 'local', exportPanel())

    expect(secretsOption).toBeEnabled()
    expect(secretsOption).not.toBeChecked()
    expect(within(exportPanel()).queryByText(en.bundle.secretsRemoteUnavailable)).toBeNull()
    await user.click(within(exportPanel()).getByRole('button', { name: en.bundle.exportButton }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/export')).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/export')[0].body))).toMatchObject({ include_secrets: false })
    expectNoEngineParameterAnywhere(fetchMock)
  })

  it('exportSelectorIsLockedWhileTheExportIsPending', async () => {
    stubDownload()
    const fetchMock = stubFetch(engineRoutes())
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()
    await selectTargetEngine(user, 'peer', exportPanel())
    const heldExport = holdPostRequests(fetchMock)

    await user.click(within(exportPanel()).getByRole('button', { name: en.bundle.exportButton }))

    const exportSelector = within(exportPanel()).getByLabelText(en.engineTarget.label)
    await waitFor(() => expect(exportSelector).toBeDisabled())
    heldExport.settle(409, { error: 'engine_has_no_sidecar' })
    expect(await within(exportPanel()).findByText(en.errors.engine_has_no_sidecar)).toBeInTheDocument()
    expect(exportSelector).toBeEnabled()
  })

  it('importSelectorIsLockedWhileThePreviewIsPending', async () => {
    const fetchMock = stubFetch(engineRoutes())
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()
    await selectTargetEngine(user, 'peer', importPanel())
    const heldPreview = holdPostRequests(fetchMock)

    await uploadAndPreview(user)

    const importSelector = within(importPanel()).getByLabelText(en.engineTarget.label)
    await waitFor(() => expect(importSelector).toBeDisabled())
    heldPreview.settle(200, makePlan('digest-peer'))
    await screen.findByRole('table', { name: en.bundle.summaryCaption })
    expect(importSelector).toBeEnabled()
    expect(importRequestUrls(fetchMock)).toEqual(['/api/import?engine=peer'])
  })

  it('localExportAndPreviewSendNoEngineParameter', async () => {
    stubDownload()
    const fetchMock = stubFetch(
      engineRoutes({
        'POST /api/export': { status: 200, body: { ok: true }, headers: EXPORT_HEADERS },
        'POST /api/import': { status: 200, body: makePlan('digest-local') },
      }),
    )
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()

    await user.click(within(exportPanel()).getByRole('button', { name: en.bundle.exportButton }))
    await uploadAndPreview(user)
    await screen.findByRole('table', { name: en.bundle.summaryCaption })

    expect(requestsTo(fetchMock, 'POST', '/api/export')).toHaveLength(1)
    expect(requestsTo(fetchMock, 'POST', '/api/import')).toHaveLength(1)
    expectNoEngineParameterAnywhere(fetchMock)
  })

  it('reportOfAnotherEngineIsNotShownAfterSwitching', async () => {
    let importCallCount = 0
    stubFetch(engineRoutes({ 'POST /api/import?engine=peer': () => ({ status: 200, body: ++importCallCount === 1 ? makePlan('digest-peer') : APPLIED_REPORT }) }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()
    await selectTargetEngine(user, 'peer', importPanel())
    await uploadAndPreview(user)
    await applyWithTypedConfirmation(user)
    expect(await within(importPanel()).findByText(en.bundle.resultTitle)).toBeInTheDocument()

    await selectTargetEngine(user, 'local', importPanel())

    expect(within(importPanel()).queryByText(en.bundle.resultTitle)).toBeNull()
    expect(within(importPanel()).queryByText('Hub collections: Applied')).toBeNull()
    expect(targetEngineNamedIn(importPanel())).toBe('local')
  })

  it('previewFailureOfAnotherEngineIsClearedAfterSwitching', async () => {
    stubFetch(engineRoutes({ 'POST /api/import?engine=peer': { status: 503, body: { error: 'sidecar_busy' } } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()
    await selectTargetEngine(user, 'peer', importPanel())
    await uploadAndPreview(user)
    expect(await within(importPanel()).findByText(en.errors.sidecar_busy)).toBeInTheDocument()

    await selectTargetEngine(user, 'local', importPanel())

    expect(within(importPanel()).queryByText(en.errors.sidecar_busy)).toBeNull()
  })

  it('translatesTheRemoteBundleErrorCodes', () => {
    for (const errorCode of ['remote_secrets_unsupported', 'engine_has_no_sidecar', 'engine_target_mismatch', 'import_conflict', 'sidecar_busy', 'sidecar_unavailable']) {
      expect(en.errors[errorCode as keyof typeof en.errors], `${errorCode} en`).toBeTruthy()
      expect(fr.errors[errorCode as keyof typeof fr.errors], `${errorCode} fr`).toBeTruthy()
    }
    for (const problemCode of ['sidecar_command_refused', 'sidecar_unavailable']) {
      expect(en.bundle.problems[problemCode as keyof typeof en.bundle.problems], `${problemCode} en`).toBeTruthy()
      expect(fr.bundle.problems[problemCode as keyof typeof fr.bundle.problems], `${problemCode} fr`).toBeTruthy()
    }
    expect(fr.bundle.secretsRemoteUnavailable).toBeTruthy()
  })

  it('remoteSecretsRefusalIsShownTranslated', async () => {
    stubFetch(engineRoutes({ 'POST /api/export?engine=peer': { status: 409, body: { error: 'remote_secrets_unsupported' } } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await waitForPanels()
    await selectTargetEngine(user, 'peer', exportPanel())

    await user.click(within(exportPanel()).getByRole('button', { name: en.bundle.exportButton }))

    expect(await within(exportPanel()).findByText(en.errors.remote_secrets_unsupported)).toBeInTheDocument()
  })
})
