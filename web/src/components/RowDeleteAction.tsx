import { useQueryClient, type QueryKey } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import { ConfirmDeleteDialog } from '@/components/ConfirmDeleteDialog'
import { Icon } from '@/components/Icon'
import { Button } from '@/components/ui/button'

interface RowDeleteActionProps {
  buttonLabel: string
  ariaLabel: string
  title: string
  description: string
  target: string
  confirmValue?: string
  engineName?: string
  request: (confirm: string) => Promise<unknown>
  invalidates: QueryKey[]
  onDeleted?: () => void
  onFailed?: (failure: unknown) => void
  disabledReason?: string
  iconOnly?: boolean
}

export function RowDeleteAction({ buttonLabel, ariaLabel, title, description, target, confirmValue, engineName, request, invalidates, onDeleted, onFailed, disabledReason, iconOnly = false }: RowDeleteActionProps) {
  const queryClient = useQueryClient()
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const pendingDeletedNotificationRef = useRef<(() => void) | null>(null)

  function finishDeletion() {
    pendingDeletedNotificationRef.current = onDeleted ?? null
    setIsDialogOpen(false)
    invalidates.forEach((queryKey) => void queryClient.invalidateQueries({ queryKey }))
  }

  function notifyDeletionOnceClosed(closeFocusEvent: Event) {
    const notifyDeleted = pendingDeletedNotificationRef.current
    pendingDeletedNotificationRef.current = null
    if (notifyDeleted) {
      closeFocusEvent.preventDefault()
      notifyDeleted()
    }
  }

  return (
    <ConfirmDeleteDialog
      open={isDialogOpen}
      trigger={
        <Button
          type="button"
          variant="destructiveOutline"
          size={iconOnly ? 'icon' : 'sm'}
          aria-label={ariaLabel}
          disabled={disabledReason !== undefined}
          title={disabledReason ?? (iconOnly ? buttonLabel : undefined)}
        >
          {iconOnly ? <Icon name="delete" /> : buttonLabel}
        </Button>
      }
      onOpen={() => setIsDialogOpen(true)}
      title={title}
      description={description}
      target={target}
      confirmValue={confirmValue}
      engineName={engineName}
      submitLabel={buttonLabel}
      request={request}
      onDeleted={finishDeletion}
      onFailed={onFailed}
      onClose={() => setIsDialogOpen(false)}
      onCloseAutoFocus={notifyDeletionOnceClosed}
    />
  )
}
