import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { confirmWebAuthn, webAuthnRegistrationOptions, type SecondFactorFlow } from '@/api/secondFactorApi'
import { createWebAuthnCredential, requireCredentialsApi } from '@/auth/webauthn'
import { FormError } from '@/components/FormError'
import { StepHeading } from '@/components/StepHeading'
import { TotpEnrollment } from '@/components/TotpEnrollment'
import { Button } from '@/components/ui/button'

type SecondFactorMethod = 'totp' | 'webauthn'

interface SecondFactorStepProps {
  flow: SecondFactorFlow
  methods: string[]
  onConfirmed(): void
  onFailure?(failure: unknown): boolean
}

function isKnownMethod(method: string): method is SecondFactorMethod {
  return method === 'totp' || method === 'webauthn'
}

export function SecondFactorStep({ flow, methods, onConfirmed, onFailure }: SecondFactorStepProps) {
  const { t } = useTranslation()
  const offeredMethods = methods.filter(isKnownMethod)
  const [chosenMethod, setChosenMethod] = useState<SecondFactorMethod | null>(
    offeredMethods.length === 1 && offeredMethods[0] === 'totp' ? 'totp' : null,
  )
  const [isRegistering, setIsRegistering] = useState(false)
  const [failure, setFailure] = useState<{ cause: unknown } | null>(null)

  async function registerWebAuthnKey() {
    setIsRegistering(true)
    setFailure(null)
    try {
      requireCredentialsApi()
      const creationOptions = await webAuthnRegistrationOptions(flow)
      const credential = await createWebAuthnCredential(creationOptions)
      await confirmWebAuthn(flow, credential)
      onConfirmed()
    } catch (registrationFailure) {
      if (!onFailure?.(registrationFailure)) setFailure({ cause: registrationFailure })
    } finally {
      setIsRegistering(false)
    }
  }

  function chooseTotp() {
    setFailure(null)
    setChosenMethod('totp')
  }

  return (
    <div className="space-y-4">
      <StepHeading title={t('enroll.secondFactor.title')} description={t('enroll.secondFactor.description')} />
      {offeredMethods.length > 1 && (
        <div className="flex flex-col gap-2">
          {offeredMethods.includes('totp') && (
            <Button type="button" variant={chosenMethod === 'totp' ? 'default' : 'outline'} onClick={chooseTotp}>
              {t('enroll.secondFactor.methodTotp')}
            </Button>
          )}
          {offeredMethods.includes('webauthn') && (
            <Button type="button" variant="outline" disabled={isRegistering} onClick={() => void registerWebAuthnKey()}>
              {isRegistering ? t('enroll.secondFactor.webauthnRegistering') : t('enroll.secondFactor.methodWebauthn')}
            </Button>
          )}
        </div>
      )}
      {chosenMethod === 'totp' && <TotpEnrollment flow={flow} onConfirmed={onConfirmed} onFailure={onFailure} />}
      {failure && <FormError failure={failure.cause} />}
    </div>
  )
}
