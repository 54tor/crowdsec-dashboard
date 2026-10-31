import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetUnauthenticatedGuard } from '@/api/client'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { initI18n, setLanguage } from '@/i18n'
import { stubFetch } from '@/test/fetchStub'
import { renderApp } from '@/test/renderApp'

const UNAUTHENTICATED = { status: 401, body: { error: 'unauthenticated' } }

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
    const fetchMock = stubFetch({ 'GET /api/auth/me': UNAUTHENTICATED })
    renderApp('/alerts')
    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    const meCalls = fetchMock.mock.calls.filter(([requestedPath]) => requestedPath === '/api/auth/me')
    expect(meCalls).toHaveLength(1)
  })

  it('doesNotLoopWhenLoginPageItselfGetsUnauthenticated', async () => {
    const fetchMock = stubFetch({ 'GET /api/auth/me': UNAUTHENTICATED })
    renderApp('/login')
    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(fetchMock.mock.calls.length).toBeLessThanOrEqual(1)
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
    await user.type(await screen.findByLabelText(en.login.password), 'wrong')
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
    await user.type(await screen.findByLabelText(en.login.password), 'correct horse')
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
})
