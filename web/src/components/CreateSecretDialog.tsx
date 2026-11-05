import { useQueryClient, type QueryKey } from '@tanstack/react-query'
import { useState } from 'react'
import { CreateSecretForm, type CreateSecretLabels } from '@/components/CreateSecretForm'
import { Button } from '@/components/ui/button'
import { PendingLockDialog } from '@/components/PendingLockDialog'

interface CreateSecretDialogProps {
  triggerLabel: string
  labels: CreateSecretLabels
  engineName: string
  invalidates: QueryKey[]
  createSecret: (name: string) => Promise<string>
}

export function CreateSecretDialog({ triggerLabel, labels, engineName, invalidates, createSecret }: CreateSecretDialogProps) {
  const queryClient = useQueryClient()
  const [isOpen, setIsOpen] = useState(false)

  function refreshLists() {
    invalidates.forEach((queryKey) => void queryClient.invalidateQueries({ queryKey }))
  }

  return (
    <PendingLockDialog open={isOpen} onOpenChange={setIsOpen} trigger={<Button type="button">{triggerLabel}</Button>}>
      {(reportPending) => (
        <CreateSecretForm
          labels={labels}
          engineName={engineName}
          createSecret={createSecret}
          onCreated={refreshLists}
          onClose={() => setIsOpen(false)}
          reportPending={reportPending}
        />
      )}
    </PendingLockDialog>
  )
}
