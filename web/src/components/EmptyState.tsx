import type { ReactNode } from 'react'
import { Icon } from '@/components/Icon'

interface EmptyStateProps {
  message: string
  action?: ReactNode
}

export function EmptyState({ message, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-md border border-dashed bg-card px-4 py-8 text-center text-sm text-muted-foreground">
      <Icon name="inbox" className="size-8" />
      <p>{message}</p>
      {action}
    </div>
  )
}
