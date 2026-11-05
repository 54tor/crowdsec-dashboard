import { useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { EngineTargetNote } from '@/components/EngineTargetNote'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { SecretReveal } from '@/components/SecretReveal'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'
import { validateResourceName } from '@/lib/nameValidation'

export interface CreateSecretLabels {
  title: string
  description: string
  nameLabel: string
  secretLabel: string
}

interface CreateSecretFormProps {
  labels: CreateSecretLabels
  engineName: string
  createSecret: (name: string) => Promise<string>
  onCreated: () => void
  onClose: () => void
  reportPending: (isPending: boolean) => void
}

export function CreateSecretForm({ labels, engineName, createSecret, onCreated, onClose, reportPending }: CreateSecretFormProps) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [secret, setSecret] = useState<string | null>(null)
  const [isPending, setIsPending] = useState(false)
  const [failure, setFailure] = useState<unknown>(null)
  const isSubmitting = useRef(false)
  usePendingReport(isPending, reportPending)
  const nameError = name === '' ? null : validateResourceName(name)
  const isValid = name !== '' && !nameError

  async function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (!isValid || isSubmitting.current) {
      return
    }
    isSubmitting.current = true
    setIsPending(true)
    setFailure(null)
    try {
      setSecret(await createSecret(name))
      onCreated()
    } catch (creationFailure) {
      setFailure(creationFailure)
    } finally {
      isSubmitting.current = false
      setIsPending(false)
    }
  }

  function close() {
    setSecret(null)
    onClose()
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{labels.title}</DialogTitle>
        <DialogDescription>{labels.description}</DialogDescription>
      </DialogHeader>
      <EngineTargetNote engineName={engineName} />
      {secret === null ? (
        <FormField
          id="create-secret-name"
          label={labels.nameLabel}
          value={name}
          onChange={(changeEvent) => setName(changeEvent.target.value)}
          error={nameError && t(`errors.${nameError}`)}
        />
      ) : (
        <div className="space-y-3">
          <p role="alert" className="text-sm font-medium text-destructive">
            {t('secret.warning')}
          </p>
          <SecretReveal label={labels.secretLabel} secret={secret} />
        </div>
      )}
      {failure !== null && <ErrorNotice error={failure} />}
      <DialogFooter>
        {secret === null ? (
          <>
            <Button type="button" variant="outline" disabled={isPending} onClick={close}>
              {t('dialog.cancel')}
            </Button>
            <Button type="submit" disabled={!isValid || isPending}>
              {isPending ? t('dialog.working') : t('secret.create')}
            </Button>
          </>
        ) : (
          <Button type="button" onClick={close}>
            {t('secret.done')}
          </Button>
        )}
      </DialogFooter>
    </form>
  )
}
