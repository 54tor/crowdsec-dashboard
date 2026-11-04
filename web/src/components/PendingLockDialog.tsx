import { useState, type ReactNode } from 'react'
import { Dialog, DialogContent, DialogTrigger } from '@/components/ui/dialog'

interface PendingLockDialogProps {
  open: boolean
  onOpenChange: (isOpen: boolean) => void
  trigger: ReactNode
  contentClassName?: string
  onCloseAutoFocus?: (closeFocusEvent: Event) => void
  children: (reportPending: (isPending: boolean) => void) => ReactNode
}

export function PendingLockDialog({ open, onOpenChange, trigger, contentClassName, onCloseAutoFocus, children }: PendingLockDialogProps) {
  const [isPending, setIsPending] = useState(false)

  function preventCloseWhilePending(closeEvent: Event) {
    if (isPending) {
      closeEvent.preventDefault()
    }
  }

  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isPending && onOpenChange(isOpen)}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent
        showCloseButton={false}
        className={contentClassName}
        onEscapeKeyDown={preventCloseWhilePending}
        onPointerDownOutside={preventCloseWhilePending}
        onInteractOutside={preventCloseWhilePending}
        onCloseAutoFocus={onCloseAutoFocus}
      >
        {children(setIsPending)}
      </DialogContent>
    </Dialog>
  )
}
