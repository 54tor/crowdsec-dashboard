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
  request: (confirm: string) => Promise<unknown>
  invalidates: QueryKey[]
  onDeleted?: () => void
  onFailed?: (failure: unknown) => void
}

export function RowDeleteAction({ buttonLabel, ariaLabel, title, description, target, request, invalidates, onDeleted, onFailed }: RowDeleteActionProps) {
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
        <Button type="button" variant="destructive" size="sm" aria-label={ariaLabel}>
          {buttonLabel}
        </Button>
      }
      onOpen={() => setIsDialogOpen(true)}
      title={title}
      description={description}
      target={target}
      submitLabel={buttonLabel}
      request={request}
      onDeleted={finishDeletion}
      onFailed={onFailed}
      onClose={() => setIsDialogOpen(false)}
    />
  )
}
