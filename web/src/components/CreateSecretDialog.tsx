import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { CreateSecretForm, type CreateSecretLabels } from '@/components/CreateSecretForm'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogTrigger } from '@/components/ui/dialog'
import { HEALTH_QUERY_KEY } from '@/hooks/useReadResources'

interface CreateSecretDialogProps {
  triggerLabel: string
  labels: CreateSecretLabels
  createSecret: (name: string) => Promise<string>
}

export function CreateSecretDialog({ triggerLabel, labels, createSecret }: CreateSecretDialogProps) {
  const queryClient = useQueryClient()
  const [isOpen, setIsOpen] = useState(false)

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button type="button">{triggerLabel}</Button>
      </DialogTrigger>
      <DialogContent showCloseButton={false}>
        <CreateSecretForm
          labels={labels}
          createSecret={createSecret}
          onCreated={() => void queryClient.invalidateQueries({ queryKey: HEALTH_QUERY_KEY })}
          onClose={() => setIsOpen(false)}
        />
      </DialogContent>
    </Dialog>
  )
}
