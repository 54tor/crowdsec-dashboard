import { useState, type FormEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { FormField } from '@/components/FormField'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'

interface TypedConfirmDialogProps {
  idPrefix: string
  trigger: ReactNode
  title: string
  description: string
  confirmWord: string
  submitLabel: string
  isRunning: boolean
  run: (typedWord: string) => Promise<void>
}

interface TypedConfirmFormProps extends Omit<TypedConfirmDialogProps, 'trigger'> {
  onClose: () => void
  reportPending: (isPending: boolean) => void
}

function TypedConfirmForm({ idPrefix, title, description, confirmWord, submitLabel, isRunning, run, onClose, reportPending }: TypedConfirmFormProps) {
  const { t } = useTranslation()
  const [typedWord, setTypedWord] = useState('')
  usePendingReport(isRunning, reportPending)
  const isMatching = typedWord === confirmWord

  async function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (!isMatching || isRunning) {
      return
    }
    await run(typedWord)
    onClose()
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{description}</DialogDescription>
      </DialogHeader>
      <FormField
        id={`${idPrefix}-confirm`}
        label={t('bundle.typeToConfirm', { word: confirmWord })}
        value={typedWord}
        onChange={(changeEvent) => setTypedWord(changeEvent.target.value)}
      />
      <DialogFooter>
        <Button type="button" variant="outline" disabled={isRunning} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" variant="destructive" disabled={!isMatching || isRunning}>
          {isRunning ? t('dialog.working') : submitLabel}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function TypedConfirmDialog({ trigger, ...formProps }: TypedConfirmDialogProps) {
  const [isOpen, setIsOpen] = useState(false)
  return (
    <PendingLockDialog open={isOpen} onOpenChange={setIsOpen} trigger={trigger}>
      {(reportPending) => <TypedConfirmForm {...formProps} onClose={() => setIsOpen(false)} reportPending={reportPending} />}
    </PendingLockDialog>
  )
}
