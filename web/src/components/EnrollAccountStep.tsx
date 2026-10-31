import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { FormError } from '@/components/FormError'
import { LabelledInput } from '@/components/LabelledInput'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/auth/useAuth'

export interface EnrollStepProps {
  onComplete(): void
}

export function EnrollAccountStep({ onComplete }: EnrollStepProps) {
  const { t } = useTranslation()
  const { enroll } = useAuth()
  const [enrollmentToken, setEnrollmentToken] = useState('')
  const [accountName, setAccountName] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [enrollError, setEnrollError] = useState<{ failure: unknown } | null>(null)

  async function submitEnrollment(submitEvent: FormEvent<HTMLFormElement>) {
    submitEvent.preventDefault()
    setIsSubmitting(true)
    setEnrollError(null)
    try {
      await enroll(enrollmentToken.trim(), accountName.trim(), password)
      onComplete()
    } catch (enrollFailure) {
      setEnrollError({ failure: enrollFailure })
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <form onSubmit={submitEnrollment} className="space-y-4">
      <LabelledInput
        id="enrollment-token"
        label={t('enroll.token')}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        value={enrollmentToken}
        onChange={(changeEvent) => setEnrollmentToken(changeEvent.target.value)}
      />
      <LabelledInput
        id="account-name"
        label={t('login.accountName')}
        autoComplete="username"
        autoCapitalize="none"
        spellCheck={false}
        maxLength={64}
        value={accountName}
        onChange={(changeEvent) => setAccountName(changeEvent.target.value)}
      />
      <LabelledInput
        id="password"
        label={t('login.password')}
        type="password"
        autoComplete="new-password"
        minLength={12}
        maxLength={128}
        value={password}
        onChange={(changeEvent) => setPassword(changeEvent.target.value)}
      />
      {enrollError && <FormError failure={enrollError.failure} />}
      <Button type="submit" className="w-full" disabled={isSubmitting}>
        {isSubmitting ? t('enroll.submitting') : t('enroll.submit')}
      </Button>
    </form>
  )
}
