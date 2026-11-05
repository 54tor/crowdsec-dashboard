import { QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { EngineSidecarView, EngineView } from '@/api/types'
import { AuthContext, type AccountRole, type AuthState } from '@/auth/AuthContext'
import { EngineSidecarActions } from '@/components/EngineSidecarActions'
import en from '@/i18n/en.json'
import { errorMessage } from '@/i18n'
import { sidecarErrorMessage } from '@/lib/sidecarErrors'
import { createQueryClient } from '@/queryClient'
import { makeEngine } from '@/test/fixtures'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }

const OBSERVED_FINGERPRINT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const GROUPED_FINGERPRINT = '0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567 89ab cdef'
const SIDECAR_URL = 'https://sidecar.example.com:8443'
const TRUSTED_KEY_LINE = 'kid-1 abcd0123456789'
const HOSTILE_TEXT = '<img src=x onerror=alert(1)>'

function makeSidecar(overrides: Partial<EngineSidecarView> = {}): EngineSidecarView {
  return {
    url: SIDECAR_URL,
    spki_sha256: OBSERVED_FINGERPRINT,
    key_id: 'kid-1',
    public_key: 'abcd0123456789',
    next_key_id: '',
    next_public_key: '',
    ...overrides,
  }
}

const LOCAL_ENGINE = makeEngine({ name: 'local', is_local: true, lapi_url: 'http://crowdsec:8080', machine_id: 'local-machine' })
const ENGINE_WITHOUT_SIDECAR = makeEngine({ name: 'peer' })
const ENGINE_WITH_SIDECAR = makeEngine({ name: 'peer', sidecar: makeSidecar() })
const ENGINE_WITH_STAGED_KEY = makeEngine({ name: 'peer', sidecar: makeSidecar({ next_key_id: 'kid-2', next_public_key: 'ef01' }) })

const ENROLMENT_RESPONSE = {
  status: 200,
  body: { sidecar: makeSidecar(), trusted_key_line: TRUSTED_KEY_LINE, issuer: 'dashboard.example.com', audience: 'peer' },
}

function pageRoutes(listedEngines: EngineView[], extraRoutes: RouteTable = {}): RouteTable {
  return {
    'GET /api/auth/me': ADMIN_SESSION,
    'GET /api/engines': { status: 200, body: { items: listedEngines } },
    'POST /api/engines/peer/sidecar/observe': { status: 200, body: { spki_sha256: OBSERVED_FINGERPRINT } },
    ...extraRoutes,
  }
}

async function findEngineRow(engineName: string): Promise<HTMLElement> {
  const nameCell = await screen.findByText(engineName, { selector: 'td' })
  return nameCell.closest('tr')!
}

// Opens the enrolment dialog of "peer", types the sidecar URL and fetches its fingerprint,
// which is the state every enrolment test starts from.
async function openEnrolmentWithFingerprint(user: ReturnType<typeof userEvent.setup>): Promise<HTMLElement> {
  await user.click(await screen.findByRole('button', { name: 'Enrol a sidecar for peer' }))
  const dialog = await screen.findByRole('dialog')
  await user.type(within(dialog).getByLabelText(en.engines.sidecar.url), SIDECAR_URL)
  await user.click(within(dialog).getByRole('button', { name: en.engines.sidecar.fetchFingerprint }))
  await within(dialog).findByText(GROUPED_FINGERPRINT)
  return dialog
}

function lastJsonBody(fetchMock: { mock: { calls: unknown[][] } }, method: string, url: string): Record<string, unknown> {
  const matchingRequests = requestsTo(fetchMock, method, url)
  return JSON.parse(String(matchingRequests[matchingRequests.length - 1].body))
}

function authStateFor(accountRole: AccountRole | null): AuthState {
  const unusedAction = vi.fn()
  return {
    isAuthenticated: accountRole !== null,
    accountName: accountRole === null ? null : 'bob',
    accountRole,
    roleError: false,
    retryRoleRefresh: unusedAction,
    login: unusedAction,
    verifySecondFactor: unusedAction,
    completeLoginSetup: unusedAction,
    enroll: unusedAction,
    completeEnrollment: unusedAction,
    logout: unusedAction,
  }
}

// Renders the sidecar actions alone with a chosen role: the Engines route itself redirects
// non-admin accounts, so the component gate is only observable outside the page.
function renderSidecarActionsAs(accountRole: AccountRole | null, engine: EngineView) {
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <AuthContext.Provider value={authStateFor(accountRole)}>
        <EngineSidecarActions engine={engine} />
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

const SIDECAR_ERROR_CODES = [
  'sidecar_fingerprint_changed',
  'sidecar_url_change_requires_removal',
  'sidecar_rename_requires_removal',
  'sidecar_next_key_changed',
  'sidecar_issuer_missing',
  'sidecar_auth_failed',
  'sidecar_unavailable',
  'sidecar_fingerprint_mismatch',
  'sidecar_clock_skew',
  'sidecar_command_refused',
  'sidecar_no_next_key',
  'engine_has_no_sidecar',
  'sidecar_busy',
  'confirmation_required',
] as const

describe('engines page sidecar management', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('enrolsASidecarOnlyAfterTheFingerprintIsConfirmed', async () => {
    const fetchMock = stubFetch(pageRoutes([ENGINE_WITHOUT_SIDECAR], { 'PUT /api/engines/peer/sidecar': ENROLMENT_RESPONSE }))
    const user = userEvent.setup()
    renderApp('/engines')

    const dialog = await openEnrolmentWithFingerprint(user)
    const pinButton = within(dialog).getByRole('button', { name: en.engines.sidecar.pinAndEnrol })
    expect(within(dialog).getByText(en.engines.sidecar.compareFingerprint)).toBeInTheDocument()
    expect(pinButton).toBeDisabled()
    expect(lastJsonBody(fetchMock, 'POST', '/api/engines/peer/sidecar/observe')).toEqual({ url: SIDECAR_URL })

    await user.click(within(dialog).getByLabelText(en.engines.sidecar.fingerprintMatches))
    expect(pinButton).toBeEnabled()
    await user.click(pinButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'PUT', '/api/engines/peer/sidecar')).toHaveLength(1))
    expect(lastJsonBody(fetchMock, 'PUT', '/api/engines/peer/sidecar')).toEqual({ url: SIDECAR_URL, spki_sha256: OBSERVED_FINGERPRINT, confirm: 'peer' })
  })

  it('showsTheTrustedKeyLineAndEnvironmentAfterEnrolment', async () => {
    stubFetch(pageRoutes([ENGINE_WITHOUT_SIDECAR], { 'PUT /api/engines/peer/sidecar': ENROLMENT_RESPONSE }))
    const user = userEvent.setup()
    renderApp('/engines')

    const dialog = await openEnrolmentWithFingerprint(user)
    await user.click(within(dialog).getByLabelText(en.engines.sidecar.fingerprintMatches))
    await user.click(within(dialog).getByRole('button', { name: en.engines.sidecar.pinAndEnrol }))

    expect(await within(dialog).findByText(en.engines.sidecar.enrolledTitle)).toBeInTheDocument()
    expect(within(dialog).getByText(TRUSTED_KEY_LINE, { selector: 'code' })).toBeInTheDocument()
    expect(within(dialog).getByText('SIDECAR_ISSUER=dashboard.example.com', { selector: 'code' })).toBeInTheDocument()
    expect(within(dialog).getByText('SIDECAR_AUDIENCE=peer', { selector: 'code' })).toBeInTheDocument()
  })

  it('copyButtonsCopyTheExactText', async () => {
    stubFetch(pageRoutes([ENGINE_WITHOUT_SIDECAR], { 'PUT /api/engines/peer/sidecar': ENROLMENT_RESPONSE }))
    const user = userEvent.setup()
    renderApp('/engines')
    const dialog = await openEnrolmentWithFingerprint(user)
    await user.click(within(dialog).getByLabelText(en.engines.sidecar.fingerprintMatches))
    await user.click(within(dialog).getByRole('button', { name: en.engines.sidecar.pinAndEnrol }))
    await within(dialog).findByText(en.engines.sidecar.enrolledTitle)

    const copyCases = [
      { label: en.engines.sidecar.trustedKeyLine, expectedClipboardText: TRUSTED_KEY_LINE },
      { label: en.engines.sidecar.issuerLine, expectedClipboardText: 'SIDECAR_ISSUER=dashboard.example.com' },
      { label: en.engines.sidecar.audienceLine, expectedClipboardText: 'SIDECAR_AUDIENCE=peer' },
    ]
    for (const copyCase of copyCases) {
      await user.click(within(dialog).getByRole('button', { name: `Copy: ${copyCase.label}` }))
      expect(await navigator.clipboard.readText()).toBe(copyCase.expectedClipboardText)
    }
  })

  it('fingerprintChangedConflictShowsTheNoticeWithoutClaimingSuccess', async () => {
    const fingerprintChanged = { status: 409, body: { error: 'sidecar_fingerprint_changed' } }
    stubFetch(pageRoutes([ENGINE_WITHOUT_SIDECAR], { 'PUT /api/engines/peer/sidecar': fingerprintChanged }))
    const user = userEvent.setup()
    renderApp('/engines')

    const dialog = await openEnrolmentWithFingerprint(user)
    await user.click(within(dialog).getByLabelText(en.engines.sidecar.fingerprintMatches))
    await user.click(within(dialog).getByRole('button', { name: en.engines.sidecar.pinAndEnrol }))

    expect(await within(dialog).findByText(en.errors.sidecar_fingerprint_changed)).toBeInTheDocument()
    expect(within(dialog).queryByText(en.engines.sidecar.enrolledTitle)).toBeNull()
    expect(within(dialog).queryByText(GROUPED_FINGERPRINT)).toBeNull()
    expect(within(dialog).getByRole('button', { name: en.engines.sidecar.pinAndEnrol })).toBeDisabled()
  })

  it('clearsTheFingerprintAndTheConfirmationWhenANewObservationFails', async () => {
    const observationOutcomes = [
      { status: 200, body: { spki_sha256: OBSERVED_FINGERPRINT } },
      { status: 502, body: { error: 'sidecar_unavailable' } },
    ]
    let observationCount = 0
    stubFetch(pageRoutes([ENGINE_WITHOUT_SIDECAR], { 'POST /api/engines/peer/sidecar/observe': () => observationOutcomes[observationCount++] }))
    const user = userEvent.setup()
    renderApp('/engines')

    const dialog = await openEnrolmentWithFingerprint(user)
    await user.click(within(dialog).getByLabelText(en.engines.sidecar.fingerprintMatches))
    expect(within(dialog).getByRole('button', { name: en.engines.sidecar.pinAndEnrol })).toBeEnabled()
    await user.click(within(dialog).getByRole('button', { name: en.engines.sidecar.fetchFingerprint }))

    expect(await within(dialog).findByText(en.errors.sidecar_unavailable)).toBeInTheDocument()
    expect(within(dialog).queryByText(GROUPED_FINGERPRINT)).toBeNull()
    expect(within(dialog).getByRole('button', { name: en.engines.sidecar.pinAndEnrol })).toBeDisabled()
  })

  it('namesTheSidecarKeyOnlyWhenTheEngineHasASidecar', async () => {
    const unreadableSecret = { status: 500, body: { error: 'engine_secret_unreadable' } }
    stubFetch(pageRoutes([ENGINE_WITHOUT_SIDECAR], { 'POST /api/engines/peer/sidecar/observe': unreadableSecret }))
    const user = userEvent.setup()
    const withoutSidecar = renderApp('/engines')
    await user.click(await screen.findByRole('button', { name: 'Enrol a sidecar for peer' }))
    const dialogWithoutSidecar = await screen.findByRole('dialog')
    await user.type(within(dialogWithoutSidecar).getByLabelText(en.engines.sidecar.url), SIDECAR_URL)
    await user.click(within(dialogWithoutSidecar).getByRole('button', { name: en.engines.sidecar.fetchFingerprint }))
    expect(await within(dialogWithoutSidecar).findByText(en.errors.engine_secret_unreadable)).toBeInTheDocument()
    expect(within(dialogWithoutSidecar).queryByText(en.engines.sidecar.unusable)).toBeNull()
    withoutSidecar.unmount()

    stubFetch(pageRoutes([ENGINE_WITH_SIDECAR], { 'POST /api/engines/peer/sidecar/observe': unreadableSecret }))
    renderApp('/engines')
    await user.click(await screen.findByRole('button', { name: 'Re-pin the sidecar certificate of peer' }))
    const dialogWithSidecar = await screen.findByRole('dialog')
    await user.click(within(dialogWithSidecar).getByRole('button', { name: en.engines.sidecar.fetchFingerprint }))
    expect(await within(dialogWithSidecar).findByText(en.engines.sidecar.unusable)).toBeInTheDocument()
  })

  it('explainsThatARepinLeavesTheKeysUnchanged', async () => {
    stubFetch(pageRoutes([ENGINE_WITH_SIDECAR], { 'PUT /api/engines/peer/sidecar': ENROLMENT_RESPONSE }))
    const user = userEvent.setup()
    renderApp('/engines')
    await user.click(await screen.findByRole('button', { name: 'Re-pin the sidecar certificate of peer' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: en.engines.sidecar.fetchFingerprint }))
    await within(dialog).findByText(GROUPED_FINGERPRINT)
    await user.click(within(dialog).getByLabelText(en.engines.sidecar.fingerprintMatches))
    await user.click(within(dialog).getByRole('button', { name: en.engines.sidecar.pinAndEnrol }))

    expect(await within(dialog).findByText(en.engines.sidecar.repinnedTitle)).toBeInTheDocument()
    expect(within(dialog).getByText(en.engines.sidecar.repinnedDescription)).toBeInTheDocument()
    expect(within(dialog).queryByText(en.engines.sidecar.enrolledTitle)).toBeNull()
  })

  it('promoteIsOfferedOnlyWhenANextKeyIsStaged', async () => {
    stubFetch(pageRoutes([ENGINE_WITH_SIDECAR]))
    const { unmount } = renderApp('/engines')
    const rowWithoutStagedKey = await findEngineRow('peer')
    expect(within(rowWithoutStagedKey).getByRole('button', { name: 'Stage the next sidecar key of peer' })).toBeInTheDocument()
    expect(within(rowWithoutStagedKey).queryByRole('button', { name: 'Promote the next sidecar key of peer' })).toBeNull()
    unmount()

    const fetchMock = stubFetch(
      pageRoutes([ENGINE_WITH_STAGED_KEY], {
        'POST /api/engines/peer/sidecar/keys/promote': { status: 200, body: { sidecar: makeSidecar({ key_id: 'kid-2' }), trusted_key_line: 'kid-2 ef01' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/engines')
    const rowWithStagedKey = await findEngineRow('peer')
    await user.click(within(rowWithStagedKey).getByRole('button', { name: 'Promote the next sidecar key of peer' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: en.engines.sidecar.promote }))

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/engines/peer/sidecar/keys/promote')).toHaveLength(1))
    expect(await screen.findByText('kid-2 ef01', { selector: 'code' })).toBeInTheDocument()
  })

  it('removingTheSidecarRequiresTheTypedEngineName', async () => {
    const fetchMock = stubFetch(pageRoutes([ENGINE_WITH_SIDECAR], { 'DELETE /api/engines/peer/sidecar': { status: 200, body: { status: 'removed' } } }))
    const user = userEvent.setup()
    renderApp('/engines')
    const engineRow = await findEngineRow('peer')

    const removeTrigger = within(engineRow).getByRole('button', { name: 'Remove the sidecar of peer' })
    expect(removeTrigger).not.toHaveAttribute('data-variant', 'destructive')
    await user.click(removeTrigger)
    const dialog = await screen.findByRole('dialog')
    const submitButton = within(dialog).getByRole('button', { name: en.engines.sidecar.remove })
    expect(submitButton).toHaveAttribute('data-variant', 'destructive')

    await user.type(within(dialog).getByRole('textbox'), 'pee')
    expect(submitButton).toBeDisabled()
    await user.type(within(dialog).getByRole('textbox'), 'r')
    await user.click(submitButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/engines/peer/sidecar')).toHaveLength(1))
    expect(lastJsonBody(fetchMock, 'DELETE', '/api/engines/peer/sidecar')).toEqual({ confirm: 'peer' })
  })

  it('engineWithoutSidecarOffersOnlyEnrolment', async () => {
    stubFetch(pageRoutes([ENGINE_WITHOUT_SIDECAR]))
    renderApp('/engines')
    const engineRow = await findEngineRow('peer')

    expect(within(engineRow).getByRole('button', { name: 'Enrol a sidecar for peer' })).toBeInTheDocument()
    expect(within(engineRow).getByText(en.engines.sidecar.badgeNone)).toBeInTheDocument()
    for (const absentActionName of ['Test the sidecar of peer', 'Stage the next sidecar key of peer', 'Promote the next sidecar key of peer', 'Remove the sidecar of peer']) {
      expect(within(engineRow).queryByRole('button', { name: absentActionName })).toBeNull()
    }
  })

  it('localEngineHasNoSidecarAction', async () => {
    stubFetch(pageRoutes([LOCAL_ENGINE]))
    renderApp('/engines')
    const localRow = await findEngineRow('local')

    expect(within(localRow).queryByRole('button', { name: /sidecar/i })).toBeNull()
    expect(within(localRow).queryByText(en.engines.sidecar.badgeNone)).toBeNull()
  })

  it('readOnlyAccountSeesNoSidecarAction', async () => {
    // A null role is the loading session: the gate must stay closed until the role is known.
    for (const accountRole of ['read_only', null] as const) {
      for (const engine of [ENGINE_WITHOUT_SIDECAR, ENGINE_WITH_STAGED_KEY]) {
        const { container, unmount } = renderSidecarActionsAs(accountRole, engine)
        expect(container).toBeEmptyDOMElement()
        unmount()
      }
    }
    const { unmount } = renderSidecarActionsAs('admin', ENGINE_WITHOUT_SIDECAR)
    expect(screen.getByRole('button', { name: 'Enrol a sidecar for peer' })).toBeInTheDocument()
    unmount()
  })

  it('hostileSidecarUrlIsRenderedAsText', async () => {
    const hostileEngine = makeEngine({ name: 'peer', sidecar: makeSidecar({ url: HOSTILE_TEXT }) })
    stubFetch(pageRoutes([hostileEngine]))
    renderApp('/engines')
    const engineRow = await findEngineRow('peer')

    expect(within(engineRow).getByText(HOSTILE_TEXT)).toBeInTheDocument()
    expect(within(engineRow).getByText(en.engines.sidecar.badgeConfigured, { selector: '[data-slot="badge"]' })).toBeInTheDocument()
    expect(engineRow.querySelector('img')).toBeNull()
  })

  it('translatesEverySidecarErrorCode', () => {
    for (const errorCode of SIDECAR_ERROR_CODES) {
      const expectedMessage = en.errors[errorCode]
      expect(expectedMessage).toBeTruthy()
      expect(sidecarErrorMessage({ code: errorCode })).toBe(expectedMessage)
      expect(errorMessage({ code: errorCode })).toBe(expectedMessage)
    }
    expect(sidecarErrorMessage({ code: 'engine_secret_unreadable' })).toBe(en.engines.sidecar.unusable)
  })
})
