import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router'
import type { LoginProgress } from '@/api/loginApi'
import { AuthPageShell } from '@/components/AuthPageShell'
import { LoginPasswordForm } from '@/components/LoginPasswordForm'
import { LoginSecondFactor } from '@/components/LoginSecondFactor'
import { LoginSetup } from '@/components/LoginSetup'
import { useAuth } from '@/auth/useAuth'
import { useEnrollmentStatus } from '@/auth/useEnrollmentStatus'

interface LoginState {
  progress: LoginProgress | null
  restartFailure: unknown
}

const INITIAL_LOGIN_STATE: LoginState = { progress: null, restartFailure: null }

export function Login() {
  const { t } = useTranslation()
  const { isAuthenticated } = useAuth()
  const { isPending: isStatusPending, isEnrollmentRequired } = useEnrollmentStatus()
  const [loginState, setLoginState] = useState<LoginState>(INITIAL_LOGIN_STATE)

  if (isAuthenticated) {
    return <Navigate to="/alerts" replace />
  }
  if (isStatusPending) {
    return <AuthPageShell title={t('login.title')} description={t('login.description')} isLoading />
  }
  if (isEnrollmentRequired) {
    return <Navigate to="/enroll" replace />
  }

  const { progress, restartFailure } = loginState
  const restart = (failure: unknown) => setLoginState({ progress: null, restartFailure: failure })

  return (
    <AuthPageShell title={t('login.title')} description={t('login.description')}>
      {progress === null && (
        <LoginPasswordForm
          initialFailure={restartFailure}
          onProgress={(nextProgress) => setLoginState({ progress: nextProgress, restartFailure: null })}
        />
      )}
      {progress?.stage === 'second_factor' && <LoginSecondFactor methods={progress.methods} onRestart={restart} />}
      {progress?.stage === 'setup' && <LoginSetup methods={progress.methods} onRestart={restart} />}
    </AuthPageShell>
  )
}
