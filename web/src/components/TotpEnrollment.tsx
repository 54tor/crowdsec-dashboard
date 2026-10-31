import { QRCodeSVG } from 'qrcode.react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { beginTotp, confirmTotp, type SecondFactorFlow, type TotpEnrollmentDetails } from '@/api/secondFactorApi'
import { FormError } from '@/components/FormError'
import { LabelledInput } from '@/components/LabelledInput'
import { Button } from '@/components/ui/button'

interface TotpEnrollmentProps {
  flow: SecondFactorFlow
  onConfirmed(): void
}

export function TotpEnrollment({ flow, onConfirmed }: TotpEnrollmentProps) {
  const { t } = useTranslation()
  const [details, setDetails] = useState<TotpEnrollmentDetails | null>(null)
  const [code, setCode] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [failure, setFailure] = useState<{ cause: unknown } | null>(null)

  useEffect(() => {
    let isCancelled = false
    beginTotp(flow).then(
      (beginResponse) => {
        if (!isCancelled) setDetails(beginResponse)
      },
      (beginFailure) => {
        if (!isCancelled) setFailure({ cause: beginFailure })
      },
    )
    return () => {
      isCancelled = true
    }
  }, [flow])

  async function submitCode(submitEvent: FormEvent<HTMLFormElement>) {
    submitEvent.preventDefault()
    setIsSubmitting(true)
    setFailure(null)
    try {
      await confirmTotp(flow, code.trim())
      onConfirmed()
    } catch (confirmFailure) {
      setFailure({ cause: confirmFailure })
    } finally {
      setIsSubmitting(false)
    }
  }

  if (!details) {
    return failure ? <FormError failure={failure.cause} /> : <p className="text-sm text-muted-foreground">{t('enroll.secondFactor.loadingTotp')}</p>
  }

  return (
    <form onSubmit={submitCode} className="space-y-4">
      <p className="text-sm text-muted-foreground">{t('enroll.secondFactor.totpIntro')}</p>
      <div className="flex justify-center rounded-md bg-white p-3">
        <QRCodeSVG
          value={details.otpauth_url}
          size={176}
          role="img"
          aria-label={t('enroll.secondFactor.qrLabel')}
        />
      </div>
      <div className="space-y-1">
        <p className="text-sm">{t('enroll.secondFactor.secretLabel')}</p>
        <code className="block break-all rounded-md bg-muted p-2 text-sm">{details.secret}</code>
      </div>
      <LabelledInput
        id="totp-code"
        label={t('enroll.secondFactor.codeLabel')}
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]{6}"
        maxLength={6}
        value={code}
        onChange={(changeEvent) => setCode(changeEvent.target.value)}
      />
      {failure && <FormError failure={failure.cause} />}
      <Button type="submit" className="w-full" disabled={isSubmitting}>
        {isSubmitting ? t('enroll.secondFactor.confirming') : t('enroll.secondFactor.confirm')}
      </Button>
    </form>
  )
}
