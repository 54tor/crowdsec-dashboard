import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router'
import { AuthPageShell } from '@/components/AuthPageShell'
import { FormError } from '@/components/FormError'
import { LabelledInput } from '@/components/LabelledInput'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/auth/useAuth'
import { useEnrollmentStatus } from '@/auth/useEnrollmentStatus'

export function Login() {
  const { t } = useTranslation()
  const { isAuthenticated, login } = useAuth()
  const { isPending: isStatusPending, isEnrollmentRequired } = useEnrollmentStatus()
  const [accountName, setAccountName] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [loginError, setLoginError] = useState<{ failure: unknown } | null>(null)

  if (isAuthenticated) {
    return <Navigate to="/alerts" replace />
  }
  if (isStatusPending) {
    return <p className="p-6 text-sm text-muted-foreground">{t('common.loading')}</p>
  }
  if (isEnrollmentRequired) {
    return <Navigate to="/enroll" replace />
  }

  async function submitLogin(submitEvent: FormEvent<HTMLFormElement>) {
    submitEvent.preventDefault()
    setIsSubmitting(true)
    setLoginError(null)
    try {
      await login(accountName.trim(), password)
    } catch (loginFailure) {
      setLoginError({ failure: loginFailure })
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <AuthPageShell title={t('login.title')} description={t('login.description')}>
      <form onSubmit={submitLogin} className="space-y-4">
        <LabelledInput
          id="account-name"
          label={t('login.accountName')}
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          value={accountName}
          onChange={(changeEvent) => setAccountName(changeEvent.target.value)}
        />
        <LabelledInput
          id="password"
          label={t('login.password')}
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(changeEvent) => setPassword(changeEvent.target.value)}
        />
        {loginError && <FormError failure={loginError.failure} />}
        <Button type="submit" className="w-full" disabled={isSubmitting}>
          {isSubmitting ? t('login.submitting') : t('login.submit')}
        </Button>
      </form>
    </AuthPageShell>
  )
}
