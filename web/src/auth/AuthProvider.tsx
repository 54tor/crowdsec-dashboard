import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, type ReactNode } from 'react'
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

async function fetchSessionState(): Promise<SessionState> {
  try {
    const meResponse = await apiFetch<{ account_name?: string; account_role?: string }>('/api/auth/me')
    return { accountName: meResponse.account_name ?? null, accountRole: parseAccountRole(meResponse.account_role) }
  } catch (sessionError) {
    if (sessionError instanceof ApiError && sessionError.code === 'unauthenticated') {
      return false
    }
    throw sessionError
  }
}

async function refreshAccountRole(queryClient: QueryClient): Promise<void> {
  try {
    const meResponse = await fetch('/api/auth/me', { credentials: 'same-origin' })
    if (!meResponse.ok) {
      return
    }
    const sessionIdentity = (await meResponse.json()) as { account_name?: string; account_role?: string }
    queryClient.setQueryData<SessionState>(SESSION_QUERY_KEY, (currentState) =>
      currentState ? { ...currentState, accountRole: parseAccountRole(sessionIdentity.account_role) } : currentState,
    )
  } catch {
    return
  }
}

function openSession(queryClient: QueryClient, accountName: string | null): void {
  resetUnauthenticatedGuard()
  queryClient.setQueryData(SESSION_QUERY_KEY, { accountName, accountRole: null } satisfies SessionIdentity as SessionState)
  void refreshAccountRole(queryClient)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const pendingAccountName = useRef<string | null>(null)
  const sessionQuery = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionState })

  useEffect(() => {
    setUnauthenticatedHandler(() => queryClient.setQueryData(SESSION_QUERY_KEY, false))
    return () => setUnauthenticatedHandler(null)
  }, [queryClient])

  const authState = useMemo<AuthState>(
    () => ({
      isAuthenticated: Boolean(sessionQuery.data),
      accountName: sessionQuery.data ? sessionQuery.data.accountName : null,
      accountRole: sessionQuery.data ? sessionQuery.data.accountRole : null,
      async login(accountName, password) {
        const loginProgress = await beginLogin(accountName, password)
        pendingAccountName.current = accountName
        return loginProgress
      },
      async verifySecondFactor(method, value) {
        await verifyLoginSecondFactor(method, value)
        openSession(queryClient, pendingAccountName.current)
      },
      async completeLoginSetup() {
        await completeLoginSetup()
        openSession(queryClient, pendingAccountName.current)
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
        openSession(queryClient, pendingAccountName.current)
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
        queryClient.removeQueries({ predicate: (cachedQuery) => cachedQuery.queryKey[0] !== SESSION_QUERY_KEY[0] })
        queryClient.setQueryData(SESSION_QUERY_KEY, false)
      },
    }),
    [queryClient, sessionQuery.data],
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
  return <AuthContext.Provider value={authState}>{children}</AuthContext.Provider>
}
