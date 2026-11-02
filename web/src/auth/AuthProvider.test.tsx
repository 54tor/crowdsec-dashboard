import { QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { apiFetch } from '@/api/client'
import { createQueryClient } from '@/queryClient'
import { stubFetch } from '@/test/fetchStub'
import { AuthProvider } from './AuthProvider'
import { useAuth } from './useAuth'

function RoleProbe() {
  const { accountRole, isAuthenticated, login, verifySecondFactor, roleError } = useAuth()
  return (
    <div>
      <p data-testid="role">{String(accountRole)}</p>
      <p data-testid="authenticated">{String(isAuthenticated)}</p>
      <p data-testid="role-error">{String(roleError)}</p>
      <button onClick={() => void login('alice', 'password')}>login</button>
      <button onClick={() => void verifySecondFactor('totp', '123456')}>verify</button>
      <button onClick={() => void apiFetch('/api/anything').catch(() => undefined)}>call-api</button>
    </div>
  )
}

function renderProbe(queryClient = createQueryClient()) {
  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RoleProbe />
      </AuthProvider>
    </QueryClientProvider>,
  )
}

describe('AuthProvider', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('exposeLeRoleDuCompteDepuisApiAuthMe', async () => {
    stubFetch({
      'GET /api/auth/me': { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'read_only' } },
    })
    renderProbe()
    expect(await screen.findByTestId('role')).toHaveTextContent('read_only')
  })

  it('traiteUnRoleInconnuCommeAbsent', async () => {
    stubFetch({
      'GET /api/auth/me': { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'root' } },
    })
    renderProbe()
    expect(await screen.findByTestId('role')).toHaveTextContent('null')
  })

  describe('rafraichissementDuRole', () => {
    const UNAUTHENTICATED = { status: 401, body: { error: 'unauthenticated' } }
    const ADMIN_ME = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }

    async function loginThroughSecondFactor() {
      const user = userEvent.setup()
      await screen.findByTestId('role')
      await user.click(screen.getByText('login'))
      await user.click(screen.getByText('verify'))
    }

    it('leRoleAdminSurvitAUneErreurTransitoireDeMe', async () => {
      let meCallCount = 0
      stubFetch({
        'GET /api/auth/me': () => {
          meCallCount += 1
          if (meCallCount === 1) return UNAUTHENTICATED
          return meCallCount === 2 ? { status: 500, body: { error: 'unknown' } } : ADMIN_ME
        },
        'POST /api/auth/login': { status: 200, body: { status: 'second_factor_required', methods: ['totp'] } },
        'POST /api/auth/login/totp': { status: 200, body: {} },
      })
      renderProbe()
      await loginThroughSecondFactor()
      await waitFor(() => expect(screen.getByTestId('role')).toHaveTextContent('admin'))
      expect(screen.getByTestId('role-error')).toHaveTextContent('false')
    })

    it('retenteUneFoisPuisSignaleLEchecEtPermetDeReessayer', async () => {
      let meShouldFail = false
      let isInitialSessionCheck = true
      stubFetch({
        'GET /api/auth/me': () => {
          if (isInitialSessionCheck) {
            isInitialSessionCheck = false
            return UNAUTHENTICATED
          }
          return meShouldFail ? { status: 500, body: { error: 'unknown' } } : ADMIN_ME
        },
        'POST /api/auth/login': { status: 200, body: { status: 'second_factor_required', methods: ['totp'] } },
        'POST /api/auth/login/totp': { status: 200, body: {} },
      })
      const fetchMock = vi.mocked(fetch)
      renderProbe()
      const user = userEvent.setup()
      await user.click(await screen.findByText('login'))
      meShouldFail = true
      await user.click(screen.getByText('verify'))
      await waitFor(() => expect(screen.getByTestId('role-error')).toHaveTextContent('true'))
      const meCalls = fetchMock.mock.calls.filter(([path]) => path === '/api/auth/me').length
      expect(meCalls).toBe(3)
      meShouldFail = false
      await user.click(screen.getByRole('button', { name: /retry|réessayer/i }))
      await waitFor(() => expect(screen.getByTestId('role')).toHaveTextContent('admin'))
      expect(screen.getByTestId('role-error')).toHaveTextContent('false')
    })
  })

  it('lExpirationDeSessionVideLeCacheDesRequetes', async () => {
    stubFetch({
      'GET /api/auth/me': { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } },
      'GET /api/anything': { status: 401, body: { error: 'unauthenticated' } },
    })
    const queryClient = createQueryClient()
    queryClient.setQueryData(['alerts'], ['donnee du premier compte'])
    renderProbe(queryClient)
    const user = userEvent.setup()
    await user.click(await screen.findByText('call-api'))
    await waitFor(() => expect(screen.getByTestId('authenticated')).toHaveTextContent('false'))
    expect(queryClient.getQueryData(['alerts'])).toBeUndefined()
  })
})
