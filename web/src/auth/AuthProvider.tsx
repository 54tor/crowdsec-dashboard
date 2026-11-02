import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ApiError, apiFetch, resetUnauthenticatedGuard, setUnauthenticatedHandler } from '@/api/client'
import { beginLogin, completeLoginSetup, verifyLoginSecondFactor } from '@/api/loginApi'
import { completeSetup } from '@/api/secondFactorApi'
import { Button } from '@/components/ui/button'
import { AuthContext, type AccountRole, type AuthState } from './AuthContext'
import { ENROLLMENT_STATUS_QUERY_KEY } from './useEnrollmentStatus'

const SESSION_QUERY_KEY = ['session']

interface SessionIdentity {
  accountName: string | null
  accountRole: AccountRole | null
}

function parseAccountRole(rawRole: string | undefined): AccountRole | null {
  return rawRole === 'admin' || rawRole === 'read_only' ? rawRole : null
}

type SessionState = SessionIdentity | false

const ROLE_REFRESH_RETRY_DELAY_MS = 300

async function fetchSessionIdentity(): Promise<SessionIdentity> {
  const meResponse = await apiFetch<{ account_name?: string; account_role?: string }>('/api/auth/me')
  return { accountName: meResponse.account_name ?? null, accountRole: parseAccountRole(meResponse.account_role) }
}

function isUnauthenticatedError(error: unknown): boolean {
  return error instanceof ApiError && error.code === 'unauthenticated'
}

async function fetchSessionState(): Promise<SessionState> {
  try {
    return await fetchSessionIdentity()
  } catch (sessionError) {
    if (isUnauthenticatedError(sessionError)) {
      return false
    }
    throw sessionError
  }
}

async function refreshAccountRole(queryClient: QueryClient): Promise<boolean> {
  for (let attemptNumber = 1; attemptNumber <= 2; attemptNumber += 1) {
    try {
      const sessionIdentity = await fetchSessionIdentity()
      queryClient.setQueryData<SessionState>(SESSION_QUERY_KEY, (currentState) =>
        currentState ? { ...currentState, accountRole: sessionIdentity.accountRole } : currentState,
      )
      return true
    } catch (refreshError) {
      if (isUnauthenticatedError(refreshError)) {
        return true
      }
      if (attemptNumber === 1) {
        await new Promise((resolve) => setTimeout(resolve, ROLE_REFRESH_RETRY_DELAY_MS))
      }
    }
  }
  return false
}

function clearCachedData(queryClient: QueryClient): void {
  queryClient.removeQueries({ predicate: (cachedQuery) => cachedQuery.queryKey[0] !== SESSION_QUERY_KEY[0] })
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const pendingAccountName = useRef<string | null>(null)
  const [roleError, setRoleError] = useState(false)
  const sessionQuery = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionState })

  const refreshRole = useCallback(async () => {
    const refreshSucceeded = await refreshAccountRole(queryClient)
    setRoleError(!refreshSucceeded)
  }, [queryClient])

  const openSession = useCallback(
    (accountName: string | null) => {
      resetUnauthenticatedGuard()
      setRoleError(false)
      queryClient.setQueryData(SESSION_QUERY_KEY, { accountName, accountRole: null } satisfies SessionIdentity as SessionState)
      void refreshRole()
    },
    [queryClient, refreshRole],
  )

  const retryRoleRefresh = useCallback(() => {
    setRoleError(false)
    void refreshRole()
  }, [refreshRole])

  useEffect(() => {
    setUnauthenticatedHandler(() => {
      setRoleError(false)
      clearCachedData(queryClient)
      queryClient.setQueryData(SESSION_QUERY_KEY, false)
    })
    return () => setUnauthenticatedHandler(null)
  }, [queryClient])

  const authState = useMemo<AuthState>(
    () => ({
      isAuthenticated: Boolean(sessionQuery.data),
      accountName: sessionQuery.data ? sessionQuery.data.accountName : null,
      accountRole: sessionQuery.data ? sessionQuery.data.accountRole : null,
      roleError,
      retryRoleRefresh,
      async login(accountName, password) {
        const loginProgress = await beginLogin(accountName, password)
        pendingAccountName.current = accountName
        return loginProgress
      },
      async verifySecondFactor(method, value) {
        await verifyLoginSecondFactor(method, value)
        openSession(pendingAccountName.current)
      },
      async completeLoginSetup() {
        await completeLoginSetup()
        openSession(pendingAccountName.current)
      },
      async enroll(enrollmentToken, accountName, password) {
        const enrollResponse = await apiFetch<{ methods: string[] }>('/api/auth/enroll', {
          method: 'POST',
          body: JSON.stringify({ token: enrollmentToken, account_name: accountName, password }),
        })
        pendingAccountName.current = accountName
        return { methods: enrollResponse.methods }
      },
      async completeEnrollment(enrollmentToken) {
        await completeSetup({ basePath: '/api/auth/enroll', extraBody: { token: enrollmentToken } })
        openSession(pendingAccountName.current)
        queryClient.setQueryData(ENROLLMENT_STATUS_QUERY_KEY, { enrollment_required: false })
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
        clearCachedData(queryClient)
        queryClient.setQueryData(SESSION_QUERY_KEY, false)
      },
    }),
    [queryClient, sessionQuery.data, roleError, retryRoleRefresh, openSession],
  )

  if (sessionQuery.isPending) {
    return <p className="p-6 text-sm text-muted-foreground">{t('common.loading')}</p>
  }
  if (sessionQuery.isError) {
    const errorCode = sessionQuery.error instanceof ApiError ? sessionQuery.error.code : 'network'
    return (
      <div role="alert" className="flex flex-col items-start gap-3 p-6 text-sm">
        <p>{t(`errors.${errorCode}`, { defaultValue: t('errors.network') })}</p>
        <Button onClick={() => void sessionQuery.refetch()}>{t('common.retry')}</Button>
      </div>
    )
  }
  return (
    <AuthContext.Provider value={authState}>
      {roleError && (
        <div role="alert" className="flex items-center gap-3 border-b px-4 py-2 text-sm">
          <p>{t('auth.roleRefreshFailed')}</p>
          <Button size="sm" variant="outline" onClick={retryRoleRefresh}>
            {t('common.retry')}
          </Button>
        </div>
      )}
      {children}
    </AuthContext.Provider>
  )
}
