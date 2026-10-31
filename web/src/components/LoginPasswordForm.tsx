import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { LoginProgress } from '@/api/loginApi'
import { FormError } from '@/components/FormError'
import { LabelledInput } from '@/components/LabelledInput'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/auth/useAuth'

interface LoginPasswordFormProps {
  initialFailure: unknown
  onProgress(progress: LoginProgress): void
}

export function LoginPasswordForm({ initialFailure, onProgress }: LoginPasswordFormProps) {
  const { t } = useTranslation()
  const { login } = useAuth()
  const [accountName, setAccountName] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [loginError, setLoginError] = useState<{ failure: unknown } | null>(
    initialFailure ? { failure: initialFailure } : null,
  )

  async function submitLogin(submitEvent: FormEvent<HTMLFormElement>) {
    submitEvent.preventDefault()
    if (isSubmitting) return
    setIsSubmitting(true)
    setLoginError(null)
    try {
      onProgress(await login(accountName.trim().toLowerCase(), password))
    } catch (loginFailure) {
      setLoginError({ failure: loginFailure })
      setIsSubmitting(false)
    }
  }

  return (
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
  )
}
