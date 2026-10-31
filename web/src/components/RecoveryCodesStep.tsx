import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { fetchRecoveryCodes, type SecondFactorFlow } from '@/api/secondFactorApi'
import { FormError } from '@/components/FormError'
import { StepHeading } from '@/components/StepHeading'
import { Button } from '@/components/ui/button'

interface RecoveryCodesStepProps {
  flow: SecondFactorFlow
  onFinish(): Promise<void>
}

const DOWNLOAD_FILE_NAME = 'recovery-codes.txt'

function downloadAsTextFile(text: string): void {
  const downloadUrl = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  const downloadLink = document.createElement('a')
  downloadLink.href = downloadUrl
  downloadLink.download = DOWNLOAD_FILE_NAME
  downloadLink.click()
  URL.revokeObjectURL(downloadUrl)
}

export function RecoveryCodesStep({ flow, onFinish }: RecoveryCodesStepProps) {
  const { t } = useTranslation()
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)
  const [isAcknowledged, setIsAcknowledged] = useState(false)
  const [hasCopied, setHasCopied] = useState(false)
  const [isFinishing, setIsFinishing] = useState(false)
  const [failure, setFailure] = useState<{ cause: unknown } | null>(null)

  useEffect(() => {
    let isCancelled = false
    fetchRecoveryCodes(flow).then(
      (fetchedCodes) => {
        if (!isCancelled) setRecoveryCodes(fetchedCodes)
      },
      (fetchFailure) => {
        if (!isCancelled) setFailure({ cause: fetchFailure })
      },
    )
    return () => {
      isCancelled = true
    }
  }, [flow])

  async function copyCodes() {
    try {
      await navigator.clipboard.writeText((recoveryCodes ?? []).join('\n'))
      setHasCopied(true)
    } catch {
      setHasCopied(false)
    }
  }

  async function finish() {
    setIsFinishing(true)
    setFailure(null)
    try {
      await onFinish()
    } catch (finishFailure) {
      setFailure({ cause: finishFailure })
      setIsFinishing(false)
    }
  }

  return (
    <div className="space-y-4">
      <StepHeading title={t('enroll.recoveryCodes.title')} description={t('enroll.recoveryCodes.description')} />
      {recoveryCodes ? (
        <>
          <ul aria-label={t('enroll.recoveryCodes.listLabel')} className="grid grid-cols-2 gap-2 rounded-md bg-muted p-3">
            {recoveryCodes.map((recoveryCode) => (
              <li key={recoveryCode}>
                <code className="text-sm">{recoveryCode}</code>
              </li>
            ))}
          </ul>
          <div className="flex gap-2">
            <Button type="button" variant="outline" onClick={() => void copyCodes()}>
              {hasCopied ? t('enroll.recoveryCodes.copied') : t('enroll.recoveryCodes.copy')}
            </Button>
            <Button type="button" variant="outline" onClick={() => downloadAsTextFile(recoveryCodes.join('\n'))}>
              {t('enroll.recoveryCodes.download')}
            </Button>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={isAcknowledged} onChange={(changeEvent) => setIsAcknowledged(changeEvent.target.checked)} />
            {t('enroll.recoveryCodes.acknowledge')}
          </label>
        </>
      ) : (
        !failure && <p className="text-sm text-muted-foreground">{t('enroll.recoveryCodes.loading')}</p>
      )}
      {failure && <FormError failure={failure.cause} />}
      <Button type="button" className="w-full" disabled={!recoveryCodes || !isAcknowledged || isFinishing} onClick={() => void finish()}>
        {isFinishing ? t('enroll.recoveryCodes.finishing') : t('enroll.recoveryCodes.finish')}
      </Button>
    </div>
  )
}
