import type { ReactNode } from 'react'
import { Navigate } from 'react-router'
import { useAuth } from './useAuth'
import type { AccountRole } from './AuthContext'

export function RequireRole({ role, children }: { role: AccountRole; children: ReactNode }) {
  const { accountRole } = useAuth()
  return accountRole === role ? <>{children}</> : <Navigate to="/alerts" replace />
}
