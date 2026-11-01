import { QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/queryClient'
import { stubFetch } from '@/test/fetchStub'
import { AuthProvider } from './AuthProvider'
import { useAuth } from './useAuth'

function RoleProbe() {
  const { accountRole } = useAuth()
  return <p data-testid="role">{String(accountRole)}</p>
}

function renderProbe() {
  render(
    <QueryClientProvider client={createQueryClient()}>
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
})
