import { useQueryClient, type QueryKey } from '@tanstack/react-query'
import { useState } from 'react'
import { ConfirmDeleteDialog } from '@/components/ConfirmDeleteDialog'
import { Button } from '@/components/ui/button'

interface RowDeleteActionProps {
  buttonLabel: string
  ariaLabel: string
  title: string
  description: string
  target: string
  confirmValue?: string
  request: (confirm: string) => Promise<unknown>
  invalidates: QueryKey[]
  onDeleted?: () => void
  onFailed?: (failure: unknown) => void
  disabledReason?: string
}

export function RowDeleteAction({ buttonLabel, ariaLabel, title, description, target, confirmValue, request, invalidates, onDeleted, onFailed, disabledReason }: RowDeleteActionProps) {
  const queryClient = useQueryClient()
  const [isDialogOpen, setIsDialogOpen] = useState(false)

  function finishDeletion() {
    setIsDialogOpen(false)
    onDeleted?.()
    invalidates.forEach((queryKey) => void queryClient.invalidateQueries({ queryKey }))
  }

  return (
    <ConfirmDeleteDialog
      open={isDialogOpen}
      trigger={
        <Button type="button" variant="destructive" size="sm" aria-label={ariaLabel} disabled={disabledReason !== undefined} title={disabledReason}>
          {buttonLabel}
        </Button>
      }
      onOpen={() => setIsDialogOpen(true)}
      title={title}
      description={description}
      target={target}
      confirmValue={confirmValue}
      submitLabel={buttonLabel}
      request={request}
      onDeleted={finishDeletion}
      onFailed={onFailed}
      onClose={() => setIsDialogOpen(false)}
    />
  )
}
