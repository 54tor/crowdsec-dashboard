import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ApiError, apiFetch, resetUnauthenticatedGuard, setUnauthenticatedHandler } from '@/api/client'
import { AuthContext, type AuthState } from './AuthContext'
import { ENROLLMENT_STATUS_QUERY_KEY } from './useEnrollmentStatus'

const SESSION_QUERY_KEY = ['session']

interface SessionIdentity {
  accountName: string | null
}

type SessionState = SessionIdentity | false

async function fetchSessionState(): Promise<SessionState> {
  try {
    const meResponse = await apiFetch<{ account_name?: string }>('/api/auth/me')
    return { accountName: meResponse.account_name ?? null }
  } catch (sessionError) {
    if (sessionError instanceof ApiError && sessionError.code === 'unauthenticated') {
      return false
    }
    throw sessionError
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const sessionQuery = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionState })

  useEffect(() => {
    setUnauthenticatedHandler(() => queryClient.setQueryData(SESSION_QUERY_KEY, false))
    return () => setUnauthenticatedHandler(null)
  }, [queryClient])

  const authState = useMemo<AuthState>(
    () => ({
      isAuthenticated: Boolean(sessionQuery.data),
      accountName: sessionQuery.data ? sessionQuery.data.accountName : null,
      async login(accountName, password) {
        await apiFetch('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ account_name: accountName, password }),
        })
        resetUnauthenticatedGuard()
        queryClient.setQueryData(SESSION_QUERY_KEY, { accountName } satisfies SessionIdentity as SessionState)
      },
      async enroll(enrollmentToken, accountName, password) {
        await apiFetch('/api/auth/enroll', {
          method: 'POST',
          body: JSON.stringify({ token: enrollmentToken, account_name: accountName, password }),
        })
        resetUnauthenticatedGuard()
        queryClient.setQueryData(ENROLLMENT_STATUS_QUERY_KEY, { enrollment_required: false })
        queryClient.setQueryData(SESSION_QUERY_KEY, { accountName } satisfies SessionIdentity as SessionState)
      },
      async logout() {
        try {
          await apiFetch('/api/auth/logout', { method: 'POST' })
        } catch (logoutError) {
          const isSessionAlreadyGone = logoutError instanceof ApiError && logoutError.code === 'unauthenticated'
          if (!isSessionAlreadyGone) {
            throw logoutError
          }
        }
        resetUnauthenticatedGuard()
        queryClient.removeQueries({ predicate: (cachedQuery) => cachedQuery.queryKey[0] !== SESSION_QUERY_KEY[0] })
        queryClient.setQueryData(SESSION_QUERY_KEY, false)
      },
    }),
    [queryClient, sessionQuery.data],
  )

  if (sessionQuery.isPending) {
    return <p className="p-6 text-sm text-muted-foreground">{t('common.loading')}</p>
  }
  return <AuthContext.Provider value={authState}>{children}</AuthContext.Provider>
}
