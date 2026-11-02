import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { LoginSecondFactorMethod } from '@/api/loginApi'
import { FormError } from '@/components/FormError'
import { LabelledInput } from '@/components/LabelledInput'
import { StepHeading } from '@/components/StepHeading'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/auth/useAuth'
import { useIsMounted } from '@/hooks/useIsMounted'
import { isLoginRestartFailure } from '@/lib/loginErrors'

type CodeView = 'totp' | 'recovery_code'

interface LoginSecondFactorProps {
  methods: string[]
  onRestart(failure: unknown): void
}

function stripWhitespace(rawCode: string): string {
  return rawCode.replace(/\s+/g, '')
}

export function LoginSecondFactor({ methods, onRestart }: LoginSecondFactorProps) {
  const { t } = useTranslation()
  const { verifySecondFactor } = useAuth()
  const isMounted = useIsMounted()
  const isTotpOffered = methods.includes('totp')
  const isWebAuthnOffered = methods.includes('webauthn')
  const [codeView, setCodeView] = useState<CodeView>(isTotpOffered || !isWebAuthnOffered ? 'totp' : 'recovery_code')
  const [code, setCode] = useState('')
  const [hasSwitchedView, setHasSwitchedView] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [failure, setFailure] = useState<{ cause: unknown } | null>(null)

  async function verify(method: LoginSecondFactorMethod, value?: string) {
    if (isSubmitting) return
    setIsSubmitting(true)
    setFailure(null)
    try {
      await verifySecondFactor(method, value)
    } catch (verifyFailure) {
      if (!isMounted()) return
      if (isLoginRestartFailure(verifyFailure)) {
        onRestart(verifyFailure)
        return
      }
      setFailure({ cause: verifyFailure })
      setIsSubmitting(false)
    }
  }

  function submitCode(submitEvent: FormEvent<HTMLFormElement>) {
    submitEvent.preventDefault()
    void verify(codeView, stripWhitespace(code))
  }

  function switchView(nextView: CodeView) {
    setCode('')
    setFailure(null)
    setCodeView(nextView)
    setHasSwitchedView(true)
  }

  const isTotpView = codeView === 'totp'

  return (
    <div className="space-y-4">
      <StepHeading title={t('login.secondFactor.title')} description={t('login.secondFactor.description')} />
      <form onSubmit={submitCode} className="space-y-4">
        <LabelledInput
          key={codeView}
          id="second-factor-code"
          label={t(isTotpView ? 'login.secondFactor.totpLabel' : 'login.secondFactor.recoveryLabel')}
          autoComplete={isTotpView ? 'one-time-code' : 'off'}
          inputMode={isTotpView ? 'numeric' : 'text'}
          autoCapitalize="none"
          spellCheck={false}
          autoFocus={hasSwitchedView}
          value={code}
          onChange={(changeEvent) => setCode(changeEvent.target.value)}
        />
        {failure && <FormError failure={failure.cause} />}
        <Button type="submit" className="w-full" disabled={isSubmitting}>
          {isSubmitting ? t('login.secondFactor.submitting') : t('login.secondFactor.submit')}
        </Button>
      </form>
      <div className="flex flex-col items-start gap-1">
        {isWebAuthnOffered && (
          <Button type="button" variant="link" disabled={isSubmitting} onClick={() => void verify('webauthn')}>
            {t('login.secondFactor.useSecurityKey')}
          </Button>
        )}
        {isTotpOffered && !isTotpView && (
          <Button type="button" variant="link" onClick={() => switchView('totp')}>
            {t('login.secondFactor.useTotp')}
          </Button>
        )}
        {isTotpView && (
          <Button type="button" variant="link" onClick={() => switchView('recovery_code')}>
            {t('login.secondFactor.useRecoveryCode')}
          </Button>
        )}
      </div>
    </div>
  )
}
