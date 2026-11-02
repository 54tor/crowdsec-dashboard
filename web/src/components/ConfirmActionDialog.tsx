import { useMutation } from '@tanstack/react-query'
import type { FormEvent, ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'

interface ConfirmActionDialogProps {
  open: boolean
  onOpenChange: (isOpen: boolean) => void
  trigger: ReactNode
  title: string
  description: string
  submitLabel: string
  request: () => Promise<unknown>
  onDone: () => void
  onFailed: (failure: unknown) => void
}

interface ConfirmActionFormProps extends Pick<ConfirmActionDialogProps, 'title' | 'description' | 'submitLabel' | 'request' | 'onDone' | 'onFailed'> {
  onCancel: () => void
  reportPending: (isPending: boolean) => void
}

function ConfirmActionForm({ title, description, submitLabel, request, onDone, onFailed, onCancel, reportPending }: ConfirmActionFormProps) {
  const { t } = useTranslation()
  const action = useMutation({ mutationFn: request, onSuccess: onDone, onError: onFailed })
  usePendingReport(action.isPending, reportPending)

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (!action.isPending) {
      action.mutate()
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{description}</DialogDescription>
      </DialogHeader>
      <DialogFooter>
        <Button type="button" variant="outline" disabled={action.isPending} onClick={onCancel}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" variant="destructive" disabled={action.isPending}>
          {action.isPending ? t('dialog.working') : submitLabel}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function ConfirmActionDialog({ open, onOpenChange, trigger, ...formProps }: ConfirmActionDialogProps) {
  return (
    <PendingLockDialog open={open} onOpenChange={onOpenChange} trigger={trigger}>
      {(reportPending) => <ConfirmActionForm {...formProps} onCancel={() => onOpenChange(false)} reportPending={reportPending} />}
    </PendingLockDialog>
  )
}
