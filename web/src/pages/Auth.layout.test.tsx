import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { deferredResponse, prepareEnglishApp } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ENROLLMENT_TOKEN = 'T'.repeat(43)
const PASSWORD = 'correct horse battery'
const TOTP_SECRET = 'JBSWY3DPEHPK3PXP'
const RECOVERY_CODES = ['rcode-aaaa-1111', 'rcode-bbbb-2222']
const UNAUTHENTICATED = { status: 401, body: { error: 'unauthenticated' } }
const BRAND_LOGO_SELECTOR = 'img[src="/crowdsec-logo.png"]'

function enrollmentRoutes(): RouteTable {
  return {
    'GET /api/auth/status': { status: 200, body: { enrollment_required: true } },
    'GET /api/auth/me': UNAUTHENTICATED,
    'POST /api/auth/enroll': { status: 200, body: { status: 'second_factor_required', methods: ['totp'] } },
    'POST /api/auth/enroll/totp': {
      status: 200,
      body: { secret: TOTP_SECRET, otpauth_url: `otpauth://totp/dashboard:alice?secret=${TOTP_SECRET}` },
    },
    'POST /api/auth/enroll/totp/confirm': { status: 200, body: { status: 'ok' } },
    'POST /api/auth/enroll/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } },
  }
}

async function reachTotpStep(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText(en.enroll.token), ENROLLMENT_TOKEN)
  await user.type(screen.getByLabelText(en.login.accountName), 'alice')
  await user.type(screen.getByLabelText(en.login.password), PASSWORD)
  await user.click(screen.getByRole('button', { name: en.enroll.submit }))
  await screen.findByLabelText(en.enroll.secondFactor.codeLabel)
}

async function reachRecoveryCodesStep(user: ReturnType<typeof userEvent.setup>) {
  await reachTotpStep(user)
  await user.type(screen.getByLabelText(en.enroll.secondFactor.codeLabel), '123456')
  await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.confirm }))
  await screen.findByText(RECOVERY_CODES[0])
}

describe('authentication pages layout', () => {
  beforeEach(async () => {
    await prepareEnglishApp()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
    sessionStorage.clear()
  })

  it('loginLoadingUsesTheShell', async () => {
    const pendingStatus = deferredResponse()
    vi.stubGlobal('fetch', vi.fn(async (requestedPath: RequestInfo | URL) => (String(requestedPath) === '/api/auth/status' ? pendingStatus.promise : new Response(JSON.stringify(UNAUTHENTICATED.body), { status: 401 }))))
    const { container } = renderApp('/login')

    const loadingStatus = await screen.findByRole('status')
    expect(loadingStatus).toHaveTextContent(en.common.loading)
    expect(loadingStatus.tagName).not.toBe('P')
    expect(container.querySelector(BRAND_LOGO_SELECTOR)).not.toBeNull()
    expect(container.querySelector('main')).toContainElement(loadingStatus)
  })

  it('authSubmitButtonsArePrimaryAndFullWidthOnMobile', async () => {
    stubFetch({ ...enrollmentRoutes(), 'GET /api/auth/status': { status: 200, body: { enrollment_required: false } } })
    renderApp('/login')

    const loginButton = await screen.findByRole('button', { name: en.login.submit })
    expect(loginButton).toHaveAttribute('data-variant', 'default')
    expect(loginButton).toHaveClass('w-full')
  })

  it('enrollSubmitButtonsArePrimaryAndFullWidthOnMobile', async () => {
    stubFetch(enrollmentRoutes())
    const user = userEvent.setup()
    renderApp('/enroll')

    const accountButton = await screen.findByRole('button', { name: en.enroll.submit })
    expect(accountButton).toHaveAttribute('data-variant', 'default')
    expect(accountButton).toHaveClass('w-full')
    await user.type(screen.getByLabelText(en.enroll.token), ENROLLMENT_TOKEN)
    await user.type(screen.getByLabelText(en.login.accountName), 'alice')
    await user.type(screen.getByLabelText(en.login.password), PASSWORD)
    await user.click(accountButton)
    const confirmButton = await screen.findByRole('button', { name: en.enroll.secondFactor.confirm })
    expect(confirmButton).toHaveAttribute('data-variant', 'default')
    expect(confirmButton).toHaveClass('w-full')
  })

  it('totpQrCodeStaysBlackOnAWhiteTile', async () => {
    stubFetch(enrollmentRoutes())
    renderApp('/enroll')
    await reachTotpStep(userEvent.setup())

    const qrTile = screen.getByRole('img', { name: en.enroll.secondFactor.qrLabel }).parentElement
    expect(qrTile).toHaveClass('bg-white', 'p-3')
    expect(screen.getByText(TOTP_SECRET)).toHaveClass('font-mono', 'bg-secondary')
  })

  it('recoveryCodesAreMono', async () => {
    stubFetch(enrollmentRoutes())
    renderApp('/enroll')
    await reachRecoveryCodesStep(userEvent.setup())

    const codeList = screen.getByRole('list', { name: en.enroll.recoveryCodes.listLabel })
    expect(codeList).toHaveClass('bg-secondary', 'font-mono')
  })

  it('secondFactorStepsKeepOneHeading', async () => {
    stubFetch(enrollmentRoutes())
    renderApp('/enroll')
    await reachTotpStep(userEvent.setup())

    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getAllByRole('heading', { level: 2 })).toHaveLength(1)
  })
})
