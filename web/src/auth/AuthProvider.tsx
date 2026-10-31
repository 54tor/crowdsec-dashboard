import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ApiError, apiFetch, resetUnauthenticatedGuard, setUnauthenticatedHandler } from '@/api/client'
import { AuthContext, type AuthState } from './AuthContext'

const SESSION_QUERY_KEY = ['session']

async function fetchSessionState(): Promise<boolean> {
  try {
    await apiFetch('/api/auth/me')
    return true
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
      isAuthenticated: sessionQuery.data === true,
      async login(password) {
        await apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify({ password }) })
        resetUnauthenticatedGuard()
        queryClient.setQueryData(SESSION_QUERY_KEY, true)
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
