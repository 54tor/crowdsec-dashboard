import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetUnauthenticatedGuard } from '@/api/client'
import { initI18n, setLanguage } from '@/i18n'
import en from '@/i18n/en.json'
import { stubFetch } from '@/test/fetchStub'
import { renderApp } from '@/test/renderApp'

const ENROLLMENT_TOKEN = 'T'.repeat(43)
const PASSWORD = 'correct horse battery'
const TOTP_SECRET = 'JBSWY3DPEHPK3PXP'
const RECOVERY_CODES = ['rcode-aaaa-1111', 'rcode-bbbb-2222']
const UNAUTHENTICATED = { status: 401, body: { error: 'unauthenticated' } }
const ENROLLMENT_OPEN = { status: 200, body: { enrollment_required: true } }
const AUTHENTICATED_ALICE = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }

function enrollmentRoutes(overrides: Record<string, unknown> = {}) {
  let hasSession = false
  return {
    'GET /api/auth/status': ENROLLMENT_OPEN,
    'GET /api/auth/me': () => (hasSession ? AUTHENTICATED_ALICE : UNAUTHENTICATED),
    'POST /api/auth/enroll': { status: 200, body: { status: 'second_factor_required', methods: ['totp'] } },
    'POST /api/auth/enroll/totp': {
      status: 200,
      body: { secret: TOTP_SECRET, otpauth_url: `otpauth://totp/dashboard:alice?secret=${TOTP_SECRET}` },
    },
    'POST /api/auth/enroll/totp/confirm': { status: 200, body: { status: 'ok' } },
    'POST /api/auth/enroll/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } },
    'POST /api/auth/enroll/complete': () => {
      hasSession = true
      return { status: 200, body: { status: 'ok' } }
    },
    ...overrides,
  } as Parameters<typeof stubFetch>[0]
}

async function submitAccountStep(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText(en.enroll.token), ENROLLMENT_TOKEN)
  await user.type(screen.getByLabelText(en.login.accountName), 'alice')
  await user.type(screen.getByLabelText(en.login.password), PASSWORD)
  await user.click(screen.getByRole('button', { name: en.enroll.submit }))
}

async function confirmTotpStep(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText(en.enroll.secondFactor.codeLabel), '123456')
  await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.confirm }))
}

describe('first account enrolment wizard', () => {
  beforeEach(async () => {
    resetUnauthenticatedGuard()
    await initI18n()
    await setLanguage('en')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
    sessionStorage.clear()
  })

  it('EnrollMovesToTheSecondFactorStepWithoutOpeningASession', async () => {
    const fetchMock = stubFetch(enrollmentRoutes())
    const user = userEvent.setup()
    const { visitedPaths } = renderApp('/enroll')
    await submitAccountStep(user)

    expect(await screen.findByRole('img', { name: en.enroll.secondFactor.qrLabel })).toBeInTheDocument()
    expect(visitedPaths).toEqual(['/enroll'])
    const enrollCall = fetchMock.mock.calls.find(([requestedPath]) => requestedPath === '/api/auth/enroll')
    expect(JSON.parse(String(enrollCall?.[1]?.body))).toEqual({ token: ENROLLMENT_TOKEN, account_name: 'alice', password: PASSWORD })
    expect(fetchMock.mock.calls.some(([requestedPath]) => requestedPath === '/api/auth/enroll/complete')).toBe(false)
  })

  it('EnrollCompletesTheJourneyAndOpensTheSession', async () => {
    const fetchMock = stubFetch(enrollmentRoutes())
    const user = userEvent.setup()
    const { visitedPaths } = renderApp('/enroll')
    await submitAccountStep(user)
    await confirmTotpStep(user)

    for (const recoveryCode of RECOVERY_CODES) {
      expect(await screen.findByText(recoveryCode)).toBeInTheDocument()
    }
    const finishButton = screen.getByRole('button', { name: en.enroll.recoveryCodes.finish })
    expect(finishButton).toBeDisabled()
    await user.click(screen.getByRole('checkbox', { name: en.enroll.recoveryCodes.acknowledge }))
    await user.click(finishButton)

    expect(await screen.findByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
    expect(visitedPaths).toEqual(['/enroll', '/alerts'])
    const completeCall = fetchMock.mock.calls.find(([requestedPath]) => requestedPath === '/api/auth/enroll/complete')
    expect(JSON.parse(String(completeCall?.[1]?.body))).toEqual({ token: ENROLLMENT_TOKEN })
  })

  it('TheTokenAndSecretsNeverReachTheUrlStorageOrConsole', async () => {
    stubFetch(enrollmentRoutes())
    const consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) => vi.spyOn(console, method))
    const user = userEvent.setup()
    renderApp('/enroll')
    await submitAccountStep(user)
    await confirmTotpStep(user)
    await screen.findByText(RECOVERY_CODES[0])

    const sensitiveValues = [ENROLLMENT_TOKEN, PASSWORD, TOTP_SECRET, ...RECOVERY_CODES]
    const storedText = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })
    for (const sensitiveValue of sensitiveValues) {
      expect(storedText).not.toContain(sensitiveValue)
    }
    const loggedText = JSON.stringify(consoleSpies.flatMap((consoleSpy) => consoleSpy.mock.calls))
    for (const sensitiveValue of sensitiveValues) {
      expect(loggedText).not.toContain(sensitiveValue)
    }
    expect(window.location.href).not.toContain(ENROLLMENT_TOKEN)
  })

  it('ADatabaseOutageDuringTheSecondFactorStepDoesNotLogTheVisitorOut', async () => {
    stubFetch(enrollmentRoutes({ 'POST /api/auth/enroll/totp/confirm': { status: 503, body: { error: 'database_unavailable' } } }))
    const user = userEvent.setup()
    const { visitedPaths, countSessionExpiredNotifications } = renderApp('/enroll')
    await submitAccountStep(user)
    await screen.findByLabelText(en.enroll.secondFactor.codeLabel)
    const expiredNotificationsBeforeOutage = countSessionExpiredNotifications()
    await confirmTotpStep(user)

    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
    expect(screen.getByLabelText(en.enroll.secondFactor.codeLabel)).toBeInTheDocument()
    expect(visitedPaths).toEqual(['/enroll'])
    expect(countSessionExpiredNotifications()).toBe(expiredNotificationsBeforeOutage)
  })

  it('EnrollShowsTheAttackerControlledMethodsAsNothingButKnownChoices', async () => {
    stubFetch(enrollmentRoutes({ 'POST /api/auth/enroll': { status: 200, body: { status: 'second_factor_required', methods: ['<img src=x onerror=alert(1)>', 'totp'] } } }))
    const user = userEvent.setup()
    const { container } = renderApp('/enroll')
    await submitAccountStep(user)
    await screen.findByRole('img', { name: en.enroll.secondFactor.qrLabel })
    await waitFor(() => expect(container.querySelector('img')).toBeNull())
  })
})
