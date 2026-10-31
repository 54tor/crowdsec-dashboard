import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch, resetUnauthenticatedGuard } from '@/api/client'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { initI18n, setLanguage } from '@/i18n'
import { makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { renderApp } from '@/test/renderApp'

async function triggerUnauthenticatedDataCalls(callCount: number): Promise<void> {
  await act(async () => {
    await Promise.allSettled(Array.from({ length: callCount }, () => apiFetch('/api/alerts')))
  })
}

const UNAUTHENTICATED = { status: 401, body: { error: 'unauthenticated' } }
const ENROLLMENT_CLOSED = { status: 200, body: { enrollment_required: false } }
const ENROLLMENT_OPEN = { status: 200, body: { enrollment_required: true } }
const AUTHENTICATED_ALICE = {
  status: 200,
  body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' },
}

async function fillLoginForm(user: ReturnType<typeof userEvent.setup>, password: string) {
  await user.type(await screen.findByLabelText(en.login.accountName), 'alice')
  await user.type(screen.getByLabelText(en.login.password), password)
}

describe('app routing and auth', () => {
  beforeEach(async () => {
    resetUnauthenticatedGuard()
    await initI18n()
    await setLanguage('en')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sendsVisitorWithoutSessionToLoginExactlyOnce', async () => {
    stubFetch({ 'GET /api/auth/me': UNAUTHENTICATED, 'GET /api/alerts': UNAUTHENTICATED })
    const { visitedPaths, countSessionExpiredNotifications } = renderApp('/alerts')
    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    await triggerUnauthenticatedDataCalls(3)
    expect(visitedPaths).toEqual(['/alerts', '/login'])
    expect(countSessionExpiredNotifications()).toBe(1)
  })

  it('doesNotLoopWhenLoginPageItselfGetsUnauthenticated', async () => {
    stubFetch({ 'GET /api/auth/me': UNAUTHENTICATED, 'GET /api/alerts': UNAUTHENTICATED })
    const { visitedPaths, countSessionExpiredNotifications } = renderApp('/login')
    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    await triggerUnauthenticatedDataCalls(3)
    expect(visitedPaths).toEqual(['/login'])
    expect(countSessionExpiredNotifications()).toBe(1)
  })

  it('redirectsToLoginWhenSessionExpiresMidSession', async () => {
    stubFetch({
      'GET /api/auth/me': { status: 200, body: { status: 'ok' } },
      'GET /api/alerts': UNAUTHENTICATED,
    })
    const { visitedPaths, countSessionExpiredNotifications } = renderApp('/decisions')
    expect(await screen.findByRole('heading', { name: en.nav.decisions })).toBeInTheDocument()
    await triggerUnauthenticatedDataCalls(3)
    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    expect(visitedPaths).toEqual(['/decisions', '/login'])
    expect(countSessionExpiredNotifications()).toBe(1)
  })

  it('guardIsResetByLoginSoLaterExpiryRedirectsAgain', async () => {
    stubFetch({
      'GET /api/auth/me': UNAUTHENTICATED,
      'POST /api/auth/login': { status: 200, body: { status: 'ok' } },
      'GET /api/alerts': UNAUTHENTICATED,
    })
    const user = userEvent.setup()
    const { visitedPaths } = renderApp('/login')
    for (let expiryNumber = 1; expiryNumber <= 2; expiryNumber += 1) {
      await fillLoginForm(user, 'correct horse')
      await user.click(screen.getByRole('button', { name: en.login.submit }))
      expect(await screen.findByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
      await triggerUnauthenticatedDataCalls(1)
      expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    }
    expect(visitedPaths).toEqual(['/login', '/alerts', '/login', '/alerts', '/login'])
  })

  it('doesNotKeepThePasswordInTheMutationCache', async () => {
    stubFetch({
      'GET /api/auth/me': UNAUTHENTICATED,
      'POST /api/auth/login': { status: 200, body: { status: 'ok' } },
    })
    const user = userEvent.setup()
    const { queryClient } = renderApp('/login')
    await fillLoginForm(user, 'correct horse')
    await user.click(screen.getByRole('button', { name: en.login.submit }))
    expect(await screen.findByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0)
  })

  it('staysLoggedInAndShowsNetworkErrorWhenLogoutRequestFails', async () => {
    const emptyAlertsPage = { status: 200, body: makePage([]) }
    const fetchMock = stubFetch({
      'GET /api/auth/me': { status: 200, body: { status: 'ok' } },
      'GET /api/alerts?page=1&per_page=20': emptyAlertsPage,
      'GET /api/alerts?page=1&per_page=100': emptyAlertsPage,
    })
    const user = userEvent.setup()
    renderApp('/alerts')
    await screen.findByRole('heading', { name: en.nav.alerts })
    fetchMock.mockRejectedValueOnce(new TypeError('offline'))
    await user.click(screen.getByRole('button', { name: en.logout }))
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.network)
    expect(screen.getByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
  })

  it.each([
    ['invalid_credentials', 401],
    ['too_many_attempts', 429],
  ])('showsTranslatedErrorOnLoginFailure %s', async (errorCode, status) => {
    stubFetch({
      'GET /api/auth/me': UNAUTHENTICATED,
      'POST /api/auth/login': { status, body: { error: errorCode } },
    })
    const user = userEvent.setup()
    renderApp('/login')
    await fillLoginForm(user, 'wrong')
    await user.click(screen.getByRole('button', { name: en.login.submit }))
    const expectedMessage = en.errors[errorCode as keyof typeof en.errors]
    expect(await screen.findByRole('alert')).toHaveTextContent(expectedMessage)

    await setLanguage('fr')
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(fr.errors[errorCode as keyof typeof fr.errors]),
    )
  })

  it('logsInThenLogsOutThroughTheApiAndReturnsToLogin', async () => {
    let hasSession = false
    const fetchMock = stubFetch({
      'GET /api/auth/me': () => (hasSession ? { status: 200, body: { status: 'ok' } } : UNAUTHENTICATED),
      'POST /api/auth/login': () => {
        hasSession = true
        return { status: 200, body: { status: 'ok' } }
      },
      'POST /api/auth/logout': () => {
        hasSession = false
        return { status: 200, body: { status: 'ok' } }
      },
    })
    const user = userEvent.setup()
    renderApp('/login')
    await fillLoginForm(user, 'correct horse')
    await user.click(screen.getByRole('button', { name: en.login.submit }))

    expect(await screen.findByRole('heading', { name: en.nav.alerts })).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: en.nav.label })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: en.logout }))
    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    const logoutCalls = fetchMock.mock.calls.filter(([requestedPath]) => requestedPath === '/api/auth/logout')
    expect(logoutCalls).toHaveLength(1)
  })

  it('marksCurrentNavigationLinkAsCurrentPage', async () => {
    stubFetch({
      'GET /api/auth/me': { status: 200, body: { status: 'ok' } },
    })
    renderApp('/hub')
    expect(await screen.findByRole('heading', { name: en.nav.hub })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: en.nav.hub })).toHaveAttribute('aria-current', 'page')
  })

  it('sendsAccountNameAndPasswordOnLogin', async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/status': ENROLLMENT_CLOSED,
      'GET /api/auth/me': UNAUTHENTICATED,
      'POST /api/auth/login': { status: 200, body: { status: 'ok' } },
    })
    const user = userEvent.setup()
    renderApp('/login')
    const accountNameInput = await screen.findByLabelText(en.login.accountName)
    expect(accountNameInput).toHaveAttribute('autocomplete', 'username')
    expect(screen.getByLabelText(en.login.password)).toHaveAttribute('autocomplete', 'current-password')
    await fillLoginForm(user, 'correct horse')
    await user.click(screen.getByRole('button', { name: en.login.submit }))
    await screen.findByRole('heading', { name: en.nav.alerts })
    const loginCall = fetchMock.mock.calls.find(([requestedPath]) => requestedPath === '/api/auth/login')
    expect(JSON.parse(String(loginCall?.[1]?.body))).toEqual({
      account_name: 'alice',
      password: 'correct horse',
    })
  })

  it('lowercasesTheAccountNameAtLogin', async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/status': ENROLLMENT_CLOSED,
      'GET /api/auth/me': UNAUTHENTICATED,
      'POST /api/auth/login': { status: 200, body: { status: 'ok' } },
    })
    const user = userEvent.setup()
    renderApp('/login')
    await user.type(await screen.findByLabelText(en.login.accountName), '  Alice ')
    await user.type(screen.getByLabelText(en.login.password), 'correct horse')
    await user.click(screen.getByRole('button', { name: en.login.submit }))
    await screen.findByRole('heading', { name: en.nav.alerts })
    const loginCall = fetchMock.mock.calls.find(([requestedPath]) => requestedPath === '/api/auth/login')
    expect(JSON.parse(String(loginCall?.[1]?.body)).account_name).toBe('alice')
  })

  it('showsRetryableDatabaseUnavailableStateWhenSessionCheckFailsAtLoad', async () => {
    let isDatabaseUp = false
    const fetchMock = stubFetch({
      'GET /api/auth/status': ENROLLMENT_CLOSED,
      'GET /api/auth/me': () =>
        isDatabaseUp
          ? { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
          : { status: 503, body: { error: 'database_unavailable' } },
    })
    const user = userEvent.setup()
    const { visitedPaths } = renderApp('/decisions')
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
    expect(visitedPaths).toEqual(['/decisions'])
    expect(screen.queryByRole('heading', { name: en.login.title })).not.toBeInTheDocument()

    isDatabaseUp = true
    await user.click(screen.getByRole('button', { name: en.common.retry }))
    expect(await screen.findByRole('heading', { name: en.nav.decisions })).toBeInTheDocument()
    expect(visitedPaths).toEqual(['/decisions'])
    const meCalls = fetchMock.mock.calls.filter(([requestedPath]) => requestedPath === '/api/auth/me')
    expect(meCalls).toHaveLength(2)
  })

  it('translatesTheSessionCheckFailureStateToFrench', async () => {
    stubFetch({ 'GET /api/auth/me': { status: 503, body: { error: 'database_unavailable' } } })
    await setLanguage('fr')
    renderApp('/decisions')
    expect(await screen.findByRole('alert')).toHaveTextContent(fr.errors.database_unavailable)
    expect(screen.getByRole('button', { name: fr.common.retry })).toBeInTheDocument()
  })

  it('translatesDatabaseUnavailableWithoutLoggingOut', async () => {
    stubFetch({
      'GET /api/auth/status': ENROLLMENT_CLOSED,
      'GET /api/auth/me': AUTHENTICATED_ALICE,
      'GET /api/alerts': { status: 503, body: { error: 'database_unavailable' } },
    })
    const { visitedPaths, countSessionExpiredNotifications } = renderApp('/decisions')
    expect(await screen.findByRole('heading', { name: en.nav.decisions })).toBeInTheDocument()
    await triggerUnauthenticatedDataCalls(2)
    expect(visitedPaths).toEqual(['/decisions'])
    expect(countSessionExpiredNotifications()).toBe(0)
  })

  it('showsDatabaseUnavailableOnLoginFailure', async () => {
    stubFetch({
      'GET /api/auth/status': ENROLLMENT_CLOSED,
      'GET /api/auth/me': UNAUTHENTICATED,
      'POST /api/auth/login': { status: 503, body: { error: 'database_unavailable' } },
    })
    const user = userEvent.setup()
    const { countSessionExpiredNotifications } = renderApp('/login')
    await fillLoginForm(user, 'correct horse')
    await user.click(screen.getByRole('button', { name: en.login.submit }))
    const alertElement = await screen.findByRole('alert')
    expect(alertElement).toHaveTextContent(en.errors.database_unavailable)
    expect(alertElement).toHaveFocus()
    expect(countSessionExpiredNotifications()).toBe(1)
  })

  it('exposesTheAccountNameFromMeInTheLayout', async () => {
    stubFetch({ 'GET /api/auth/me': AUTHENTICATED_ALICE })
    renderApp('/hub')
    expect(await screen.findByText('alice')).toBeInTheDocument()
  })

  it('redirectsLoginToEnrollWhenEnrollmentIsRequired', async () => {
    stubFetch({ 'GET /api/auth/status': ENROLLMENT_OPEN, 'GET /api/auth/me': UNAUTHENTICATED })
    const { visitedPaths } = renderApp('/login')
    expect(await screen.findByRole('heading', { name: en.enroll.title })).toBeInTheDocument()
    expect(visitedPaths).toEqual(['/login', '/enroll'])
    expect(screen.queryByRole('button', { name: en.login.submit })).not.toBeInTheDocument()
  })

  it('redirectsEnrollToLoginWhenEnrollmentIsClosed', async () => {
    stubFetch({ 'GET /api/auth/status': ENROLLMENT_CLOSED, 'GET /api/auth/me': UNAUTHENTICATED })
    const { visitedPaths } = renderApp('/enroll')
    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    expect(visitedPaths).toEqual(['/enroll', '/login'])
  })

  it('enrollFormDeclaresAutocompleteHintsAndAPasswordField', async () => {
    stubFetch({ 'GET /api/auth/status': ENROLLMENT_OPEN, 'GET /api/auth/me': UNAUTHENTICATED })
    renderApp('/enroll')
    expect(await screen.findByLabelText(en.enroll.token)).toHaveAttribute('autocomplete', 'off')
    expect(screen.getByLabelText(en.login.accountName)).toHaveAttribute('autocomplete', 'username')
    expect(screen.getByLabelText(en.login.password)).toHaveAttribute('autocomplete', 'new-password')
    expect(screen.getByLabelText(en.login.password)).toHaveAttribute('type', 'password')
  })

  it('enrollTranslatesInvalidEnrollmentToken', async () => {
    stubFetch({
      'GET /api/auth/status': ENROLLMENT_OPEN,
      'GET /api/auth/me': UNAUTHENTICATED,
      'POST /api/auth/enroll': { status: 403, body: { error: 'invalid_enrollment_token' } },
    })
    const user = userEvent.setup()
    renderApp('/enroll')
    await user.type(await screen.findByLabelText(en.enroll.token), 'wrong')
    await user.type(screen.getByLabelText(en.login.accountName), 'alice')
    await user.type(screen.getByLabelText(en.login.password), 'correct horse battery')
    await user.click(screen.getByRole('button', { name: en.enroll.submit }))
    const alertElement = await screen.findByRole('alert')
    expect(alertElement).toHaveTextContent(en.errors.invalid_enrollment_token)
    expect(alertElement).toHaveFocus()
    await setLanguage('fr')
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(fr.errors.invalid_enrollment_token))
  })
})
