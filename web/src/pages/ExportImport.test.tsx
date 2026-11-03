import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ImportPlan } from '@/api/bundleApi'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { SECTION_PROBLEM_CODES, SKIP_REASON_CODES, WARNING_CODES, SECTION_STATUS_CODES } from '@/lib/bundleCodes'
import { stubFetch } from '@/test/fetchStub'
import { holdPostRequests, prepareEnglishApp, requestsTo } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }
const ROLELESS_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'carol' } }
const PAGE_PATH = '/export-import'
const BUNDLE_CONTENT = { format: 'crowdsec-dashboard-bundle', version: 1, sections: { hub: { collections: [] }, decisions: { decisions: [] }, config: { files: [] } } }
const SECRET_MARKER = 'marqueur-secret-de-bundle'

function makePlan(overrides: Partial<ImportPlan> = {}): ImportPlan {
  return {
    sections: ['hub', 'decisions', 'config'],
    hub: [{ name: 'crowdsecurity/linux', version: '1.0' }],
    decisions: [{ scope: 'Ip', value: '203.0.113.7', scenario: 'import/2026-11-03', until: '2026-12-01T00:00:00Z' }],
    alerts: [],
    config: [{ name: 'acquis.d/web.yaml', change: 'updated', diff: '-old\n+new', diff_truncated: false }],
    skipped: [{ section: 'decisions', target: '203.0.113.9', reason: 'allowlisted' }],
    skipped_counts: { decisions: { allowlisted: 1 } },
    warnings: ['version_mismatch:crowdsecurity/nginx'],
    unavailable: [],
    unavailable_codes: {},
    digest: 'digest-from-preview',
    ...overrides,
  }
}

function adminRoutes(extraRoutes = {}, session: { status: number; body: object } = ADMIN_SESSION) {
  return { 'GET /api/auth/me': session, ...extraRoutes }
}

function bundleFile(content: unknown = BUNDLE_CONTENT): File {
  return new File([JSON.stringify(content)], 'bundle.json', { type: 'application/json' })
}

async function uploadAndPreview(user: ReturnType<typeof userEvent.setup>, content: unknown = BUNDLE_CONTENT) {
  await user.upload(await screen.findByLabelText(en.bundle.fileLabel), bundleFile(content))
  await user.click(await screen.findByRole('button', { name: en.bundle.previewButton }))
}

async function typeInDialog(user: ReturnType<typeof userEvent.setup>, word: string) {
  const dialog = await screen.findByRole('dialog')
  await user.type(within(dialog).getByLabelText(en.bundle.typeToConfirm.replace('{{word}}', word)), word)
  return dialog
}

describe('export and import page', () => {
  beforeEach(async () => {
    await prepareEnglishApp()
    localStorage.clear()
    sessionStorage.clear()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('previewShowsPerSectionCountsAndWarnings', async () => {
    stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: makePlan() } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    const summary = await screen.findByRole('table', { name: en.bundle.summaryCaption })
    const decisionsRow = within(summary).getByText(en.bundle.sections.decisions).closest('tr') as HTMLElement
    expect(within(decisionsRow).getAllByText('1').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(en.bundle.warnings.version_mismatch, { exact: false })).toBeInTheDocument()
    expect(screen.getByText('crowdsecurity/nginx', { selector: 'bdi' })).toBeInTheDocument()
  })

  it('previewShowsAllowlistedSkips', async () => {
    const plan = makePlan({ skipped_counts: { decisions: { allowlisted: 2, allowlist_unavailable: 1 } } })
    stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: plan } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    expect(await screen.findByText(en.bundle.allowlistedNotice_other.replace('{{count}}', '2'))).toBeInTheDocument()
    expect(screen.getByText(en.bundle.allowlistUnavailableNotice_one.replace('{{count}}', '1'))).toBeInTheDocument()
  })

  it('applyDisabledUntilImportRetyped', async () => {
    stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: makePlan() } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    await user.click(await screen.findByRole('button', { name: en.bundle.applyButton }))
    const dialog = await screen.findByRole('dialog')
    const submitButton = within(dialog).getByRole('button', { name: en.bundle.applyButton })
    expect(submitButton).toBeDisabled()
    await user.type(within(dialog).getByLabelText(en.bundle.typeToConfirm.replace('{{word}}', 'IMPORT')), 'IMPOR')
    expect(submitButton).toBeDisabled()
    await user.type(within(dialog).getByLabelText(en.bundle.typeToConfirm.replace('{{word}}', 'IMPORT')), 'T')
    expect(submitButton).toBeEnabled()
  })

  it('applySendsSameDigestAsPreview', async () => {
    const applyResponse = { digest: 'digest-from-preview', report: { sections: [] } }
    let callCount = 0
    const fetchMock = stubFetch(adminRoutes({ 'POST /api/import': () => ({ status: 200, body: ++callCount === 1 ? makePlan() : applyResponse }) }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    await user.click(await screen.findByRole('button', { name: en.bundle.applyButton }))
    const dialog = await typeInDialog(user, 'IMPORT')
    await user.click(within(dialog).getByRole('button', { name: en.bundle.applyButton }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/import')).toHaveLength(2))
    const [previewRequest, applyRequest] = requestsTo(fetchMock, 'POST', '/api/import').map((request) => JSON.parse(String(request.body)))
    expect(previewRequest.mode).toBe('preview')
    expect(applyRequest).toMatchObject({ mode: 'apply', digest: 'digest-from-preview', confirm: 'IMPORT', sections: ['hub', 'decisions', 'config'] })
  })

  it('applyShowsPerSectionResults', async () => {
    const report = {
      sections: [
        { section: 'hub', status: 'applied', applied: 1, skipped: 0, failed: 0, skipped_reasons: null },
        { section: 'config', status: 'failed', applied: 0, skipped: 0, failed: 1, skipped_reasons: {}, error_code: 'config_inconsistent', affected_files: ['<b>acquis.yaml</b>'] },
        { section: 'alerts', status: 'applied', applied: 1, skipped: 0, failed: 0, skipped_reasons: {}, warnings: ['simulated_decision_may_remain'] },
      ],
    }
    let callCount = 0
    stubFetch(adminRoutes({ 'POST /api/import': () => ({ status: 200, body: ++callCount === 1 ? makePlan() : { digest: 'd', report } }) }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    await user.click(await screen.findByRole('button', { name: en.bundle.applyButton }))
    const dialog = await typeInDialog(user, 'IMPORT')
    await user.click(within(dialog).getByRole('button', { name: en.bundle.applyButton }))
    expect(await screen.findByText(en.bundle.problems.config_inconsistent)).toBeInTheDocument()
    expect(screen.getByText('<b>acquis.yaml</b>', { selector: 'bdi' })).toBeInTheDocument()
    expect(screen.getByText(en.bundle.warnings.simulated_decision_may_remain)).toBeInTheDocument()
  })

  it('doesNotAllowASecondSubmitWhileApplying', async () => {
    const fetchMock = stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: makePlan() } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    await user.click(await screen.findByRole('button', { name: en.bundle.applyButton }))
    const dialog = await typeInDialog(user, 'IMPORT')
    holdPostRequests(fetchMock)
    await user.click(within(dialog).getByRole('button', { name: en.bundle.applyButton }))
    const workingButton = await within(dialog).findByRole('button', { name: en.dialog.working })
    expect(workingButton).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('importConflictInvalidatesThePreview', async () => {
    let callCount = 0
    stubFetch(adminRoutes({ 'POST /api/import': () => (++callCount === 1 ? { status: 200, body: makePlan() } : { status: 409, body: { error: 'import_conflict' } }) }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    await user.click(await screen.findByRole('button', { name: en.bundle.applyButton }))
    const dialog = await typeInDialog(user, 'IMPORT')
    await user.click(within(dialog).getByRole('button', { name: en.bundle.applyButton }))
    expect(await screen.findByText(en.errors.import_conflict)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.bundle.applyButton })).not.toBeInTheDocument()
    expect(screen.queryByRole('table', { name: en.bundle.summaryCaption })).not.toBeInTheDocument()
  })

  it('unavailableSectionDisablesApply', async () => {
    const plan = makePlan({ unavailable: ['config'], unavailable_codes: { config: 'import_disabled' } })
    stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: plan } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    expect(await screen.findByRole('button', { name: en.bundle.applyButton })).toBeDisabled()
    expect(screen.getByText(en.bundle.deselectUnavailable)).toBeInTheDocument()
  })

  it('importDisabledStateExplainsHowToEnable', async () => {
    const plan = makePlan({ unavailable: ['config'], unavailable_codes: { config: 'import_disabled' } })
    stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: plan } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    const help = await screen.findByText(en.bundle.importDisabledHelp)
    expect(help.textContent).toContain('CONFIG_IMPORT_ENABLED')
    expect(help.textContent).toContain('CONFIG_IMPORT_DIR')
  })

  it('rendersConfigDiffAsText', async () => {
    const diff = '+<script>window.injected = true</script>'
    const plan = makePlan({ config: [{ name: 'acquis.yaml', change: 'updated', diff, diff_truncated: false }] })
    stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: plan } }))
    const user = userEvent.setup()
    const { container } = renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    await screen.findByText(diff)
    expect(container.querySelector('script')).toBeNull()
  })

  it('rendersUntrustedNamesAsText', async () => {
    const hostileName = '<img src=x onerror=alert(1)>'
    const plan = makePlan({ hub: [{ name: hostileName, version: '1' }] })
    stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: plan } }))
    const user = userEvent.setup()
    const { container } = renderApp(PAGE_PATH)
    await uploadAndPreview(user)
    expect(await screen.findByText(`${hostileName} 1`, { selector: 'bdi' })).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
  })

  it('oversizedFileIsRejectedBeforeUpload', async () => {
    const fetchMock = stubFetch(adminRoutes())
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    const oversizedFile = bundleFile()
    Object.defineProperty(oversizedFile, 'size', { value: 8 * 1024 * 1024 + 1 })
    await user.upload(await screen.findByLabelText(en.bundle.fileLabel), oversizedFile)
    expect(await screen.findByText(en.errors.bundle_file_too_large)).toBeInTheDocument()
    expect(requestsTo(fetchMock, 'POST', '/api/import')).toHaveLength(0)
  })

  it('invalidJsonIsRejectedBeforeUpload', async () => {
    const fetchMock = stubFetch(adminRoutes())
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await user.upload(await screen.findByLabelText(en.bundle.fileLabel), new File(['{not json'], 'bundle.json', { type: 'application/json' }))
    expect(await screen.findByText(en.errors.bundle_file_invalid)).toBeInTheDocument()
    expect(requestsTo(fetchMock, 'POST', '/api/import')).toHaveLength(0)
  })

  it('bundleContentIsNotPersistedOrCached', async () => {
    stubFetch(adminRoutes({ 'POST /api/import': { status: 200, body: makePlan() } }))
    const user = userEvent.setup()
    const { queryClient, visitedPaths } = renderApp(PAGE_PATH)
    await uploadAndPreview(user, { ...BUNDLE_CONTENT, note: SECRET_MARKER })
    await screen.findByRole('table', { name: en.bundle.summaryCaption })
    const storedText = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })
    expect(storedText).not.toContain(SECRET_MARKER)
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.state.data))).not.toContain(SECRET_MARKER)
    expect(JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state.variables))).not.toContain(SECRET_MARKER)
    expect(window.location.href).not.toContain(SECRET_MARKER)
    expect(visitedPaths.join(' ')).not.toContain(SECRET_MARKER)
  })

  it('secretsExportRequiresRetypedConfirmation', async () => {
    const createObjectUrl = vi.fn(() => 'blob:fake')
    const revokeObjectUrl = vi.fn()
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: createObjectUrl, revokeObjectURL: revokeObjectUrl }))
    const fetchMock = stubFetch(
      adminRoutes({ 'POST /api/export': { status: 200, body: { ok: true }, headers: { 'Content-Disposition': 'attachment; filename="crowdsec-bundle-2026-11-03.json"', 'X-Bundle-Skipped-Alerts': '3' } } }),
    )
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await user.click(await screen.findByLabelText(en.bundle.includeSecrets))
    expect(screen.getByText(en.bundle.secretsWarning)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: en.bundle.exportButton }))
    const dialog = await screen.findByRole('dialog')
    const submitButton = within(dialog).getByRole('button', { name: en.bundle.exportButton })
    expect(submitButton).toBeDisabled()
    await typeInDialog(user, 'SECRETS')
    await user.click(submitButton)
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/export')).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/export')[0].body))).toMatchObject({ include_secrets: true, confirm_secrets: 'SECRETS' })
    await waitFor(() => expect(revokeObjectUrl).toHaveBeenCalledWith('blob:fake'))
    expect(await screen.findByText(en.bundle.skippedAlerts_other.replace('{{count}}', '3'))).toBeInTheDocument()
  })

  it('exportWithoutSecretsDownloadsDirectly', async () => {
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: () => 'blob:fake', revokeObjectURL: vi.fn() }))
    const fetchMock = stubFetch(adminRoutes({ 'POST /api/export': { status: 413, body: { error: 'bundle_too_large' } } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await user.click(await screen.findByRole('button', { name: en.bundle.exportButton }))
    expect(await screen.findByText(en.errors.bundle_too_large)).toBeInTheDocument()
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/export')[0].body))).toMatchObject({ include_secrets: false })
  })

  it('showsSessionRequiredMessage', async () => {
    stubFetch(adminRoutes({ 'POST /api/export': { status: 403, body: { error: 'session_required' } } }))
    const user = userEvent.setup()
    renderApp(PAGE_PATH)
    await user.click(await screen.findByRole('button', { name: en.bundle.exportButton }))
    expect(await screen.findByText(en.errors.session_required)).toBeInTheDocument()
  })

  it.each([
    ['read_only', READ_ONLY_SESSION],
    ['missing', ROLELESS_SESSION],
  ])('pageHiddenForReadOnly (%s role)', async (_label, session) => {
    stubFetch(adminRoutes({ 'GET /api/alerts?page=1&per_page=20': { status: 200, body: { items: [], page: 1, per_page: 20 } } }, session))
    const { visitedPaths } = renderApp(PAGE_PATH)
    await waitFor(() => expect(visitedPaths).toContain('/alerts'))
    expect(screen.queryByRole('link', { name: en.nav.exportImport })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: en.bundle.title })).not.toBeInTheDocument()
  })

  it('translatesEveryServerCodeInThePlan', () => {
    const groups: Array<[string, string[]]> = [
      ['skipReasons', SKIP_REASON_CODES],
      ['problems', SECTION_PROBLEM_CODES],
      ['warnings', WARNING_CODES],
      ['status', SECTION_STATUS_CODES],
    ]
    for (const [group, codes] of groups) {
      for (const code of codes) {
        const englishGroup = en.bundle[group as keyof typeof en.bundle] as Record<string, string>
        const frenchGroup = fr.bundle[group as keyof typeof fr.bundle] as Record<string, string>
        expect(englishGroup[code], `${group}.${code} en`).toBeTruthy()
        expect(frenchGroup[code], `${group}.${code} fr`).toBeTruthy()
      }
    }
    for (const errorCode of ['bundle_too_large', 'bundle_invalid', 'bundle_version', 'too_many_changes', 'operation_running', 'operation_lock_unavailable', 'import_timeout', 'section_unavailable', 'import_conflict', 'session_required']) {
      expect(en.errors[errorCode as keyof typeof en.errors], errorCode).toBeTruthy()
      expect(fr.errors[errorCode as keyof typeof fr.errors], errorCode).toBeTruthy()
    }
  })
})
