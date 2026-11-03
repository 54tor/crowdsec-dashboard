import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { createAllowlist } from '@/api/allowlistsApi'
import type { AllowlistMutation, NewAllowlistInput } from '@/api/types'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'
import { allowlistTextError, isValidAllowlistName } from '@/lib/allowlistValue'

interface CreateAllowlistDialogProps {
  engineName: string
  onWritten: (mutation: AllowlistMutation) => void
}

interface CreateAllowlistFormProps extends CreateAllowlistDialogProps {
  onClose: () => void
  reportPending: (isPending: boolean) => void
}

function CreateAllowlistForm({ engineName, onWritten, onClose, reportPending }: CreateAllowlistFormProps) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const creation = useMutation({ mutationFn: (input: NewAllowlistInput) => createAllowlist(engineName, input), onSuccess: onWritten })
  usePendingReport(creation.isPending, reportPending)

  const isNameInvalid = name !== '' && !isValidAllowlistName(name)
  const descriptionError = allowlistTextError(description)
  const isValid = isValidAllowlistName(name) && description.trim() !== '' && descriptionError === null

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (isValid && !creation.isPending) {
      creation.mutate({ name, description })
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t('allowlists.createTitle')}</DialogTitle>
        <DialogDescription>{t('allowlists.createDescription')}</DialogDescription>
      </DialogHeader>
      <FormField
        id="allowlist-name"
        label={t('allowlists.name')}
        hint={t('allowlists.nameHint')}
        value={name}
        onChange={(changeEvent) => setName(changeEvent.target.value)}
        error={isNameInvalid ? t('allowlists.nameInvalid') : null}
      />
      <FormField
        id="allowlist-description"
        label={t('allowlists.description')}
        value={description}
        onChange={(changeEvent) => setDescription(changeEvent.target.value)}
        error={descriptionError && t(`allowlists.${descriptionError}`)}
      />
      {creation.isError && <ErrorNotice error={creation.error} />}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={creation.isPending} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" disabled={!isValid || creation.isPending}>
          {creation.isPending ? t('dialog.working') : t('allowlists.createSubmit')}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function CreateAllowlistDialog({ engineName, onWritten }: CreateAllowlistDialogProps) {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)

  function finishCreation(mutation: AllowlistMutation) {
    setIsOpen(false)
    onWritten(mutation)
  }

  return (
    <PendingLockDialog open={isOpen} onOpenChange={setIsOpen} trigger={<Button type="button">{t('allowlists.create')}</Button>}>
      {(reportPending) => (
        <CreateAllowlistForm engineName={engineName} onWritten={finishCreation} onClose={() => setIsOpen(false)} reportPending={reportPending} />
      )}
    </PendingLockDialog>
  )
}
