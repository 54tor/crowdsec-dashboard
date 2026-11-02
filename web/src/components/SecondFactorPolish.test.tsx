import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetUnauthenticatedGuard } from '@/api/client'
import { RecoveryCodesStep } from '@/components/RecoveryCodesStep'
import { SecondFactorStep } from '@/components/SecondFactorStep'
import { TotpEnrollment } from '@/components/TotpEnrollment'
import { initI18n, setLanguage } from '@/i18n'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { stubFetch } from '@/test/fetchStub'
import { renderApp } from '@/test/renderApp'
import type { SecondFactorFlow } from '@/api/secondFactorApi'

const FLOW: SecondFactorFlow = { basePath: '/api/auth/enroll', extraBody: { token: 'enrollment-token-value' } }
const RECOVERY_CODES = ['aaaa-bbbb-cccc', 'dddd-eeee-ffff']
const RECOVERY_URL = '/api/auth/enroll/recovery-codes'

function installCredentials(credentials: unknown) {
  Object.defineProperty(navigator, 'credentials', { value: credentials, configurable: true })
}

describe('second factor screens polish', () => {
  beforeEach(async () => {
    resetUnauthenticatedGuard()
    await initI18n()
    await setLanguage('en')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    Reflect.deleteProperty(navigator, 'credentials')
  })

  it('retriesTheRecoveryCodesFetchAfterAFailure', async () => {
    let attemptCount = 0
    const fetchMock = stubFetch({
      [`POST ${RECOVERY_URL}`]: () => {
        attemptCount += 1
        return attemptCount === 1
          ? { status: 503, body: { error: 'database_unavailable' } }
          : { status: 200, body: { recovery_codes: RECOVERY_CODES } }
      },
    })
    const user = userEvent.setup()
    render(<RecoveryCodesStep flow={FLOW} onFinish={async () => undefined} />)

    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
    await user.click(screen.getByRole('button', { name: en.enroll.recoveryCodes.retry }))

    expect(await screen.findByText(RECOVERY_CODES[0])).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([calledPath]) => calledPath === RECOVERY_URL)).toHaveLength(2)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.enroll.recoveryCodes.retry })).not.toBeInTheDocument()
  })

  it('ignoresAWebAuthnResultArrivingAfterUnmount', async () => {
    let resolveCredential: (credential: unknown) => void = () => undefined
    installCredentials({ create: vi.fn(() => new Promise((resolve) => (resolveCredential = resolve))) })
    const fetchMock = stubFetch({
      'POST /api/auth/enroll/webauthn/options': {
        status: 200,
        body: { publicKey: { challenge: 'AQID', rp: { name: 'Dashboard' }, user: { id: 'BAUG', name: 'alice', displayName: 'alice' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }] } },
      },
      'POST /api/auth/enroll/webauthn/confirm': { status: 200, body: { status: 'ok' } },
    })
    const onConfirmed = vi.fn()
    const user = userEvent.setup()
    const { unmount } = render(<SecondFactorStep flow={FLOW} methods={['totp', 'webauthn']} onConfirmed={onConfirmed} />)
    await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.methodWebauthn }))
    await waitFor(() => expect(navigator.credentials.create).toHaveBeenCalled())

    unmount()
    await act(async () => resolveCredential({ toJSON: () => ({ id: 'credential-id' }) }))

    expect(fetchMock.mock.calls.some(([calledPath]) => calledPath === '/api/auth/enroll/webauthn/confirm')).toBe(false)
    expect(onConfirmed).not.toHaveBeenCalled()
  })

  it('pluralizesTheLockoutMinutesInBothLanguages', async () => {
    const { errorMessage } = await import('@/i18n')
    expect(errorMessage({ code: 'account_locked', retryAfterSeconds: 60 })).toBe(
      'This account is temporarily locked. Try again in 1 minute.',
    )
    expect(errorMessage({ code: 'account_locked', retryAfterSeconds: 600 })).toBe(
      'This account is temporarily locked. Try again in 10 minutes.',
    )
    await setLanguage('fr')
    expect(errorMessage({ code: 'account_locked', retryAfterSeconds: 60 })).toBe(
      'Ce compte est temporairement verrouillé. Réessayez dans 1 minute.',
    )
    expect(errorMessage({ code: 'account_locked', retryAfterSeconds: 600 })).toBe(
      'Ce compte est temporairement verrouillé. Réessayez dans 10 minutes.',
    )
    expect(fr.errors.account_locked_one).toBeDefined()
  })

  it('focusesTheCodeFieldWhenSwitchingBetweenCodeViews', async () => {
    const user = userEvent.setup()
    const loginResponse = { status: 200, body: { status: 'second_factor_required', methods: ['totp'] } }
    stubFetch({
      'GET /api/auth/status': { status: 200, body: { enrollment_required: false } },
      'GET /api/auth/me': { status: 401, body: { error: 'unauthenticated' } },
      'POST /api/auth/login': loginResponse,
    })
    renderApp('/login')
    await user.type(await screen.findByLabelText(en.login.accountName), 'alice')
    await user.type(screen.getByLabelText(en.login.password), 'correct horse battery')
    await user.click(screen.getByRole('button', { name: en.login.submit }))
    await user.click(await screen.findByRole('button', { name: en.login.secondFactor.useRecoveryCode }))
    expect(screen.getByLabelText(en.login.secondFactor.recoveryLabel)).toHaveFocus()
    await user.click(screen.getByRole('button', { name: en.login.secondFactor.useTotp }))
    expect(screen.getByLabelText(en.login.secondFactor.totpLabel)).toHaveFocus()
  })

  it('showsTheTitleAndInstructionsOfTheSecondFactorSteps', async () => {
    const user = userEvent.setup()
    stubFetch({
      'GET /api/auth/status': { status: 200, body: { enrollment_required: false } },
      'GET /api/auth/me': { status: 401, body: { error: 'unauthenticated' } },
      'POST /api/auth/login': { status: 200, body: { status: 'second_factor_required', methods: ['totp'] } },
    })
    renderApp('/login')
    await user.type(await screen.findByLabelText(en.login.accountName), 'alice')
    await user.type(screen.getByLabelText(en.login.password), 'correct horse battery')
    await user.click(screen.getByRole('button', { name: en.login.submit }))
    expect(await screen.findByRole('heading', { name: en.login.secondFactor.title })).toBeInTheDocument()
    expect(screen.getByText(en.login.secondFactor.description)).toBeInTheDocument()
  })

  it('startsAPasskeyOnlyAccountOnTheRecoveryCodeView', async () => {
    const user = userEvent.setup()
    stubFetch({
      'GET /api/auth/status': { status: 200, body: { enrollment_required: false } },
      'GET /api/auth/me': { status: 401, body: { error: 'unauthenticated' } },
      'POST /api/auth/login': { status: 200, body: { status: 'second_factor_required', methods: ['webauthn'] } },
    })
    renderApp('/login')
    await user.type(await screen.findByLabelText(en.login.accountName), 'alice')
    await user.type(screen.getByLabelText(en.login.password), 'correct horse battery')
    await user.click(screen.getByRole('button', { name: en.login.submit }))
    expect(await screen.findByLabelText(en.login.secondFactor.recoveryLabel)).toBeInTheDocument()
    expect(screen.queryByLabelText(en.login.secondFactor.totpLabel)).not.toBeInTheDocument()
  })

  it('announcesLoadingStatesWithAriaLive', async () => {
    stubFetch({
      [`POST ${RECOVERY_URL}`]: () => new Promise(() => undefined) as never,
      'POST /api/auth/enroll/totp': () => new Promise(() => undefined) as never,
    })
    const recoveryRender = render(<RecoveryCodesStep flow={FLOW} onFinish={async () => undefined} />)
    expect(screen.getByText(en.enroll.recoveryCodes.loading)).toHaveAttribute('role', 'status')
    recoveryRender.unmount()
    render(<TotpEnrollment flow={FLOW} onConfirmed={() => undefined} />)
    expect(screen.getByText(en.enroll.secondFactor.loadingTotp)).toHaveAttribute('role', 'status')
  })
})
