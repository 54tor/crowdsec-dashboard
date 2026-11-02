import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetUnauthenticatedGuard } from '@/api/client'
import { initI18n, setLanguage } from '@/i18n'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { renderApp } from '@/test/renderApp'

type FetchMock = ReturnType<typeof stubFetch>

const UNAUTHENTICATED = { status: 401, body: { error: 'unauthenticated' } }
const ENROLLMENT_CLOSED = { status: 200, body: { enrollment_required: false } }
const OK = { status: 200, body: { status: 'ok' } }
const SECOND_FACTOR_REQUIRED = { status: 200, body: { status: 'second_factor_required', methods: ['totp', 'webauthn'] } }
const TOTP_ONLY = { status: 200, body: { status: 'second_factor_required', methods: ['totp'] } }
const SETUP_REQUIRED = { status: 200, body: { status: 'second_factor_setup_required', methods: ['totp'] } }
const PENDING_EXPIRED = { status: 401, body: { error: 'pending_login_expired' } }
const RECOVERY_CODES = ['aaaa-bbbb-cccc', 'dddd-eeee-ffff']

function bodyOf(fetchMock: FetchMock, requestedPath: string): unknown {
  const matchingCall = fetchMock.mock.calls.find(([calledPath]) => calledPath === requestedPath)
  return JSON.parse(String(matchingCall?.[1]?.body))
}

function countCalls(fetchMock: FetchMock, requestedPath: string): number {
  return fetchMock.mock.calls.filter(([calledPath]) => calledPath === requestedPath).length
}

function installCredentials(credentials: unknown) {
  Object.defineProperty(navigator, 'credentials', { value: credentials, configurable: true })
}

function routes(overrides: RouteTable): RouteTable {
  return {
    'GET /api/auth/status': ENROLLMENT_CLOSED,
    'GET /api/auth/me': UNAUTHENTICATED,
    ...overrides,
  }
}

async function submitPassword(user: ReturnType<typeof userEvent.setup>, accountName = 'alice') {
  await user.type(await screen.findByLabelText(en.login.accountName), accountName)
  await user.type(screen.getByLabelText(en.login.password), 'correct horse battery')
  await user.click(screen.getByRole('button', { name: en.login.submit }))
}

async function startAtSecondFactor(overrides: RouteTable, loginResponse = SECOND_FACTOR_REQUIRED) {
  const fetchMock = stubFetch(routes({ 'POST /api/auth/login': loginResponse, ...overrides }))
  const user = userEvent.setup()
  const rendered = renderApp('/login')
  await submitPassword(user)
  await screen.findByRole('heading', { name: en.login.secondFactor.title })
  return { fetchMock, user, ...rendered }
}

describe('two-step login', () => {
  beforeEach(async () => {
    resetUnauthenticatedGuard()
    await initI18n()
    await setLanguage('en')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    Reflect.deleteProperty(navigator, 'credentials')
  })

  it('doesNotOpenTheSessionAfterThePasswordAlone', async () => {
    const { visitedPaths, fetchMock } = await startAtSecondFactor({})
    expect(visitedPaths).toEqual(['/login'])
    expect(countCalls(fetchMock, '/api/auth/login')).toBe(1)
    expect(bodyOf(fetchMock, '/api/auth/login')).toEqual({ account_name: 'alice', password: 'correct horse battery' })
    expect(screen.queryByLabelText(en.login.password)).not.toBeInTheDocument()
  })

  it('lowercasesAndTrimsTheAccountName', async () => {
    const fetchMock = stubFetch(routes({ 'POST /api/auth/login': SECOND_FACTOR_REQUIRED }))
    const user = userEvent.setup()
    renderApp('/login')
    await submitPassword(user, '  Alice ')
    await screen.findByRole('heading', { name: en.login.secondFactor.title })
    expect((bodyOf(fetchMock, '/api/auth/login') as { account_name: string }).account_name).toBe('alice')
  })

  it('submitsTheTotpCodeThenOpensTheSession', async () => {
    let hasSession = false
    const { user, fetchMock } = await startAtSecondFactor({
      'GET /api/auth/me': () => (hasSession ? { status: 200, body: { status: 'authenticated', account_name: 'alice' } } : UNAUTHENTICATED),
      'POST /api/auth/login/totp': () => {
        hasSession = true
        return OK
      },
    })
    const codeInput = screen.getByLabelText(en.login.secondFactor.totpLabel)
    expect(codeInput).toHaveAttribute('autocomplete', 'one-time-code')
    expect(codeInput).toHaveAttribute('inputmode', 'numeric')
    expect(codeInput).not.toHaveAttribute('maxlength')
    await user.type(codeInput, '123456')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
    expect(bodyOf(fetchMock, '/api/auth/login/totp')).toEqual({ code: '123456' })
  })

  it('stripsWhitespaceFromAPastedTotpCode', async () => {
    const { user, fetchMock } = await startAtSecondFactor({ 'POST /api/auth/login/totp': OK })
    await user.click(screen.getByLabelText(en.login.secondFactor.totpLabel))
    await user.paste(' 123 456 ')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    await waitFor(() => expect(countCalls(fetchMock, '/api/auth/login/totp')).toBe(1))
    expect(bodyOf(fetchMock, '/api/auth/login/totp')).toEqual({ code: '123456' })
  })

  it('acceptsARecoveryCodeThroughTheToggle', async () => {
    let hasSession = false
    const { user, fetchMock } = await startAtSecondFactor({
      'GET /api/auth/me': () => (hasSession ? { status: 200, body: { status: 'authenticated', account_name: 'alice' } } : UNAUTHENTICATED),
      'POST /api/auth/login/recovery-code': () => {
        hasSession = true
        return OK
      },
    })
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.useRecoveryCode }))
    await user.type(screen.getByLabelText(en.login.secondFactor.recoveryLabel), 'aaaa-bbbb-cccc')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
    expect(bodyOf(fetchMock, '/api/auth/login/recovery-code')).toEqual({ code: 'aaaa-bbbb-cccc' })
    expect(countCalls(fetchMock, '/api/auth/login/totp')).toBe(0)
  })

  it('switchesBackToTotpFromTheRecoveryCodeView', async () => {
    const { user } = await startAtSecondFactor({})
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.useRecoveryCode }))
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.useTotp }))
    expect(screen.getByLabelText(en.login.secondFactor.totpLabel)).toBeInTheDocument()
  })

  it('showsAnAlertAndStaysOnTheStepWhenTheCodeIsWrong', async () => {
    const { user } = await startAtSecondFactor({
      'POST /api/auth/login/totp': { status: 401, body: { error: 'invalid_code' } },
    })
    await user.type(screen.getByLabelText(en.login.secondFactor.totpLabel), '000000')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.invalid_code)
    expect(screen.getByLabelText(en.login.secondFactor.totpLabel)).toBeInTheDocument()
  })

  it('returnsToThePasswordStepWhenThePendingLoginExpired', async () => {
    const { user } = await startAtSecondFactor({ 'POST /api/auth/login/totp': PENDING_EXPIRED })
    await user.type(screen.getByLabelText(en.login.secondFactor.totpLabel), '123456')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByLabelText(en.login.password)).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(en.errors.pending_login_expired)
  })

  it('showsTheLockDurationAndReturnsToThePasswordStep', async () => {
    const { user } = await startAtSecondFactor({
      'POST /api/auth/login/totp': { status: 423, body: { error: 'account_locked' }, headers: { 'Retry-After': '600' } },
    })
    await user.type(screen.getByLabelText(en.login.secondFactor.totpLabel), '123456')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByLabelText(en.login.password)).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('10 minute')
    await setLanguage('fr')
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('10 minute'))
    expect(screen.getByRole('alert')).toHaveTextContent(fr.errors.account_locked_other.split('{{')[0])
  })

  it('showsAGenericDenialWithoutASession', async () => {
    const { user, visitedPaths } = await startAtSecondFactor({
      'POST /api/auth/login/totp': { status: 403, body: { error: 'access_denied' } },
    })
    await user.type(screen.getByLabelText(en.login.secondFactor.totpLabel), '123456')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByLabelText(en.login.password)).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(en.errors.access_denied)
    expect(visitedPaths).toEqual(['/login'])
  })

  it('showsSecondFactorSetupNotAllowed', async () => {
    const { user } = await startAtSecondFactor({
      'POST /api/auth/login/totp': { status: 403, body: { error: 'second_factor_setup_not_allowed' } },
    })
    await user.type(screen.getByLabelText(en.login.secondFactor.totpLabel), '123456')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.second_factor_setup_not_allowed)
  })

  it('keepsTheUserOnTheStepWhenTheDatabaseIsUnavailable', async () => {
    const { user } = await startAtSecondFactor({
      'POST /api/auth/login/totp': { status: 503, body: { error: 'database_unavailable' } },
    })
    await user.type(screen.getByLabelText(en.login.secondFactor.totpLabel), '123456')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
    expect(screen.getByLabelText(en.login.secondFactor.totpLabel)).toBeInTheDocument()
  })

  it('showsTooManyPendingLoginsAtThePasswordStep', async () => {
    stubFetch(routes({ 'POST /api/auth/login': { status: 503, body: { error: 'too_many_pending_logins' } } }))
    const user = userEvent.setup()
    renderApp('/login')
    await submitPassword(user)
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.too_many_pending_logins)
  })

  it('sendsOnlyOneRequestOnADoubleClick', async () => {
    const { user, fetchMock } = await startAtSecondFactor({ 'POST /api/auth/login/totp': OK })
    await user.type(screen.getByLabelText(en.login.secondFactor.totpLabel), '123456')
    await user.dblClick(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    await waitFor(() => expect(countCalls(fetchMock, '/api/auth/login/totp')).toBe(1))
  })

  it('movesFocusToTheStepHeadingAndTheErrorAlert', async () => {
    const { user } = await startAtSecondFactor({
      'POST /api/auth/login/totp': { status: 401, body: { error: 'invalid_code' } },
    })
    expect(screen.getByRole('heading', { name: en.login.secondFactor.title })).toHaveFocus()
    await user.type(screen.getByLabelText(en.login.secondFactor.totpLabel), '000000')
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.submit }))
    expect(await screen.findByRole('alert')).toHaveFocus()
  })

  it('offersTheSecurityKeyOnlyWhenTheServerListsIt', async () => {
    await startAtSecondFactor({}, TOTP_ONLY)
    expect(screen.queryByRole('button', { name: en.login.secondFactor.useSecurityKey })).not.toBeInTheDocument()
  })

  describe('with a security key', () => {
    const ASSERTION_OPTIONS = {
      status: 200,
      body: { publicKey: { challenge: 'AQID', rpId: 'dashboard.example.com', allowCredentials: [{ type: 'public-key', id: 'Bw-_' }] } },
    }

    it('signsTheChallengeThenOpensTheSession', async () => {
      const serializedAssertion = { id: 'credential-id', response: { signature: 'c2ln' } }
      const getCredential = vi.fn(async () => ({ toJSON: () => serializedAssertion }))
      installCredentials({ get: getCredential })
      let hasSession = false
      const { user, fetchMock } = await startAtSecondFactor({
        'GET /api/auth/me': () => (hasSession ? { status: 200, body: { status: 'authenticated', account_name: 'alice' } } : UNAUTHENTICATED),
        'POST /api/auth/login/webauthn/options': ASSERTION_OPTIONS,
        'POST /api/auth/login/webauthn': () => {
          hasSession = true
          return OK
        },
      })
      await user.click(screen.getByRole('button', { name: en.login.secondFactor.useSecurityKey }))
      expect(await screen.findByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
      expect(bodyOf(fetchMock, '/api/auth/login/webauthn/options')).toEqual({})
      expect(bodyOf(fetchMock, '/api/auth/login/webauthn')).toEqual({ credential: serializedAssertion })
      const requestArgument = (getCredential.mock.calls[0] as unknown as [CredentialRequestOptions])[0]
      expect(Array.from(new Uint8Array(requestArgument.publicKey?.challenge as ArrayBuffer))).toEqual([1, 2, 3])
    })

    it('showsAnAlertWhenTheUserCancelsTheCeremony', async () => {
      installCredentials({ get: vi.fn(async () => Promise.reject(new DOMException('cancelled', 'NotAllowedError'))) })
      const { user, fetchMock } = await startAtSecondFactor({ 'POST /api/auth/login/webauthn/options': ASSERTION_OPTIONS })
      await user.click(screen.getByRole('button', { name: en.login.secondFactor.useSecurityKey }))
      expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.webauthn_failed)
      expect(countCalls(fetchMock, '/api/auth/login/webauthn')).toBe(0)
      expect(screen.getByLabelText(en.login.secondFactor.totpLabel)).toBeInTheDocument()
    })

    it('showsAnAlertWhenTheServerRejectsTheAssertion', async () => {
      installCredentials({ get: vi.fn(async () => ({ toJSON: () => ({ id: 'credential-id' }) })) })
      const { user } = await startAtSecondFactor({
        'POST /api/auth/login/webauthn/options': ASSERTION_OPTIONS,
        'POST /api/auth/login/webauthn': { status: 401, body: { error: 'webauthn_failed' } },
      })
      await user.click(screen.getByRole('button', { name: en.login.secondFactor.useSecurityKey }))
      expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.webauthn_failed)
    })

    it('reportsAnUnsupportedBrowserWithoutCallingTheServer', async () => {
      const { user, fetchMock } = await startAtSecondFactor({})
      await user.click(screen.getByRole('button', { name: en.login.secondFactor.useSecurityKey }))
      expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.webauthn_unsupported)
      expect(countCalls(fetchMock, '/api/auth/login/webauthn/options')).toBe(0)
    })

    it('returnsToThePasswordStepWhenThePendingLoginExpired', async () => {
      installCredentials({ get: vi.fn() })
      const { user } = await startAtSecondFactor({ 'POST /api/auth/login/webauthn/options': PENDING_EXPIRED })
      await user.click(screen.getByRole('button', { name: en.login.secondFactor.useSecurityKey }))
      expect(await screen.findByLabelText(en.login.password)).toBeInTheDocument()
      expect(screen.getByRole('alert')).toHaveTextContent(en.errors.pending_login_expired)
    })
  })

  describe('legacy account without a second factor', () => {
    it('followsTheSetupFlowBeforeOpeningTheSession', async () => {
      let hasSession = false
      const fetchMock = stubFetch(
        routes({
          'GET /api/auth/me': () => (hasSession ? { status: 200, body: { status: 'authenticated', account_name: 'alice' } } : UNAUTHENTICATED),
          'POST /api/auth/login': SETUP_REQUIRED,
          'POST /api/auth/login/setup/totp': {
            status: 200,
            body: { secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/dashboard:alice?secret=JBSWY3DPEHPK3PXP' },
          },
          'POST /api/auth/login/setup/totp/confirm': OK,
          'POST /api/auth/login/setup/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } },
          'POST /api/auth/login/setup/complete': () => {
            hasSession = true
            return OK
          },
        }),
      )
      const user = userEvent.setup()
      const { visitedPaths } = renderApp('/login')
      await submitPassword(user)
      await user.type(await screen.findByLabelText(en.enroll.secondFactor.codeLabel), '123456')
      await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.confirm }))
      await screen.findByRole('heading', { name: en.enroll.recoveryCodes.title })
      expect(visitedPaths).toEqual(['/login'])
      await user.click(await screen.findByLabelText(en.enroll.recoveryCodes.acknowledge))
      await user.click(screen.getByRole('button', { name: en.enroll.recoveryCodes.finish }))
      expect(await screen.findByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
      expect(bodyOf(fetchMock, '/api/auth/login/setup/totp')).toEqual({})
      expect(bodyOf(fetchMock, '/api/auth/login/setup/complete')).toEqual({})
      expect(countCalls(fetchMock, '/api/auth/login/setup/totp')).toBe(1)
    })

    const TOTP_BEGIN = {
      status: 200,
      body: { secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/dashboard:alice?secret=JBSWY3DPEHPK3PXP' },
    }
    const SETUP_ROUTES: RouteTable = {
      'POST /api/auth/login/setup/totp': TOTP_BEGIN,
      'POST /api/auth/login/setup/totp/confirm': OK,
      'POST /api/auth/login/setup/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } },
    }
    const DATABASE_DOWN = { status: 503, body: { error: 'database_unavailable' } }

    async function startSetup(overrides: RouteTable, loginResponse = SETUP_REQUIRED) {
      stubFetch(routes({ 'POST /api/auth/login': loginResponse, ...SETUP_ROUTES, ...overrides }))
      const user = userEvent.setup()
      renderApp('/login')
      await submitPassword(user)
      return user
    }

    async function confirmTotpCode(user: ReturnType<typeof userEvent.setup>) {
      await user.type(await screen.findByLabelText(en.enroll.secondFactor.codeLabel), '123456')
      await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.confirm }))
    }

    async function expectBackAtPasswordWithExpiry() {
      expect(await screen.findByLabelText(en.login.password)).toBeInTheDocument()
      expect(screen.getByRole('alert')).toHaveTextContent(en.errors.pending_login_expired)
    }

    it('returnsToThePasswordStepWhenTotpBeginExpired', async () => {
      await startSetup({ 'POST /api/auth/login/setup/totp': PENDING_EXPIRED })
      await expectBackAtPasswordWithExpiry()
    })

    it('returnsToThePasswordStepWhenTotpConfirmExpired', async () => {
      const user = await startSetup({ 'POST /api/auth/login/setup/totp/confirm': PENDING_EXPIRED })
      await confirmTotpCode(user)
      await expectBackAtPasswordWithExpiry()
    })

    it('returnsToThePasswordStepWhenTheRecoveryCodesFetchExpired', async () => {
      const user = await startSetup({ 'POST /api/auth/login/setup/recovery-codes': PENDING_EXPIRED })
      await confirmTotpCode(user)
      await expectBackAtPasswordWithExpiry()
    })

    it('returnsToThePasswordStepWhenWebauthnRegistrationExpired', async () => {
      installCredentials({ create: vi.fn() })
      await startSetup(
        { 'POST /api/auth/login/setup/webauthn/options': PENDING_EXPIRED },
        { status: 200, body: { status: 'second_factor_setup_required', methods: ['totp', 'webauthn'] } },
      ).then(async (user) => {
        await user.click(await screen.findByRole('button', { name: en.enroll.secondFactor.methodWebauthn }))
      })
      await expectBackAtPasswordWithExpiry()
    })

    it('staysInTheStepWhenTotpBeginHitsAnUnavailableDatabase', async () => {
      await startSetup({ 'POST /api/auth/login/setup/totp': DATABASE_DOWN })
      expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
      expect(screen.queryByLabelText(en.login.password)).not.toBeInTheDocument()
    })

    it('staysInTheStepWhenTotpConfirmHitsAnUnavailableDatabase', async () => {
      const user = await startSetup({ 'POST /api/auth/login/setup/totp/confirm': DATABASE_DOWN })
      await confirmTotpCode(user)
      expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
      expect(screen.queryByLabelText(en.login.password)).not.toBeInTheDocument()
    })

    it('staysInTheStepWhenTheRecoveryCodesFetchHitsAnUnavailableDatabase', async () => {
      const user = await startSetup({ 'POST /api/auth/login/setup/recovery-codes': DATABASE_DOWN })
      await confirmTotpCode(user)
      expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
      expect(screen.queryByLabelText(en.login.password)).not.toBeInTheDocument()
    })

    it('staysInTheStepWhenWebauthnRegistrationHitsAnUnavailableDatabase', async () => {
      installCredentials({ create: vi.fn() })
      const user = await startSetup(
        { 'POST /api/auth/login/setup/webauthn/options': DATABASE_DOWN },
        { status: 200, body: { status: 'second_factor_setup_required', methods: ['totp', 'webauthn'] } },
      )
      await user.click(await screen.findByRole('button', { name: en.enroll.secondFactor.methodWebauthn }))
      expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
      expect(screen.queryByLabelText(en.login.password)).not.toBeInTheDocument()
    })

    it('returnsToThePasswordStepWhenCompletingAfterExpiry', async () => {
      stubFetch(
        routes({
          'POST /api/auth/login': SETUP_REQUIRED,
          'POST /api/auth/login/setup/totp': {
            status: 200,
            body: { secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/dashboard:alice?secret=JBSWY3DPEHPK3PXP' },
          },
          'POST /api/auth/login/setup/totp/confirm': OK,
          'POST /api/auth/login/setup/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } },
          'POST /api/auth/login/setup/complete': PENDING_EXPIRED,
        }),
      )
      const user = userEvent.setup()
      renderApp('/login')
      await submitPassword(user)
      await user.type(await screen.findByLabelText(en.enroll.secondFactor.codeLabel), '123456')
      await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.confirm }))
      await user.click(await screen.findByLabelText(en.enroll.recoveryCodes.acknowledge))
      await user.click(screen.getByRole('button', { name: en.enroll.recoveryCodes.finish }))
      expect(await screen.findByLabelText(en.login.password)).toBeInTheDocument()
      expect(screen.getByRole('alert')).toHaveTextContent(en.errors.pending_login_expired)
    })
  })
})
