import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { Button } from '@/components/ui/button'
import { usePendingReport } from '@/hooks/usePendingReport'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

export interface ConfirmDeleteDialogProps {
  open: boolean
  trigger: ReactNode
  title: string
  description: string
  target: string
  submitLabel: string
  request: (confirm: string) => Promise<unknown>
  onDeleted: () => void
  onFailed?: (failure: unknown) => void
  onOpen: () => void
  onClose: () => void
}

function ConfirmDeleteForm({ title, description, target, submitLabel, request, onDeleted, onFailed, onClose, reportPending }: Omit<ConfirmDeleteDialogProps, 'open' | 'trigger' | 'onOpen'> & { reportPending: (isPending: boolean) => void }) {
  const { t } = useTranslation()
  const [typedTarget, setTypedTarget] = useState('')
  const deletion = useMutation({ mutationFn: request, onSuccess: onDeleted, onError: onFailed })
  usePendingReport(deletion.isPending, reportPending)
  const isMatching = typedTarget === target

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (isMatching && !deletion.isPending) {
      deletion.mutate(typedTarget)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{description}</DialogDescription>
      </DialogHeader>
      <FormField
        id="confirm-delete-target"
        label={t('confirmDelete.label', { target })}
        hint={t('confirmDelete.hint')}
        value={typedTarget}
        onChange={(changeEvent) => setTypedTarget(changeEvent.target.value)}
      />
      {deletion.isError && <ErrorNotice error={deletion.error} />}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={deletion.isPending} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" variant="destructive" disabled={!isMatching || deletion.isPending}>
          {deletion.isPending ? t('dialog.working') : submitLabel}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function ConfirmDeleteDialog(props: ConfirmDeleteDialogProps) {
  return (
    <PendingLockDialog
      open={props.open}
      onOpenChange={(isOpen) => (isOpen ? props.onOpen() : props.onClose())}
      trigger={props.trigger}
    >
      {(reportPending) => (
        <ConfirmDeleteForm
          title={props.title}
          description={props.description}
          target={props.target}
          submitLabel={props.submitLabel}
          request={props.request}
          onDeleted={props.onDeleted}
          onFailed={props.onFailed}
          onClose={props.onClose}
          reportPending={reportPending}
        />
      )}
    </PendingLockDialog>
  )
}
