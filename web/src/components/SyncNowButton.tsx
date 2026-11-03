import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { runSync } from '@/api/syncApi'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

interface SyncNowButtonProps {
  disabled: boolean
  guardedPeerNames: string[]
  onStarted: () => void
}

function GuardedConfirmation({ guardedPeerNames, onConfirm, onCancel }: { guardedPeerNames: string[]; onConfirm: () => void; onCancel: () => void }) {
  const { t } = useTranslation()
  const [typedNames, setTypedNames] = useState<Record<string, string>>({})
  const allNamesMatch = guardedPeerNames.every((peerName) => typedNames[peerName] === peerName)

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (allNamesMatch) {
      onConfirm()
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t('sync.guardTitle')}</DialogTitle>
        <DialogDescription>{t('sync.guardDescription')}</DialogDescription>
      </DialogHeader>
      {guardedPeerNames.map((peerName, peerIndex) => (
        <FormField
          key={peerName}
          id={`sync-guard-${peerIndex}`}
          label={t('confirmDelete.label', { target: peerName })}
          value={typedNames[peerName] ?? ''}
          onChange={(changeEvent) => setTypedNames({ ...typedNames, [peerName]: changeEvent.target.value })}
        />
      ))}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" disabled={!allNamesMatch}>
          {t('sync.confirmRun')}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function SyncNowButton({ disabled, guardedPeerNames, onStarted }: SyncNowButtonProps) {
  const { t } = useTranslation()
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const run = useMutation({
    mutationFn: runSync,
    onSuccess: () => {
      setIsDialogOpen(false)
      onStarted()
    },
  })
  const hasGuardedPeers = guardedPeerNames.length > 0

  function startRun() {
    run.mutate()
  }

  return (
    <div className="space-y-2">
      <Button type="button" disabled={disabled || run.isPending} onClick={hasGuardedPeers ? () => setIsDialogOpen(true) : startRun}>
        {t('sync.syncNow')}
      </Button>
      {run.isError && !isDialogOpen && <ErrorNotice error={run.error} />}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent showCloseButton={false}>
          <GuardedConfirmation guardedPeerNames={guardedPeerNames} onConfirm={startRun} onCancel={() => setIsDialogOpen(false)} />
          {run.isError && <ErrorNotice error={run.error} />}
        </DialogContent>
      </Dialog>
    </div>
  )
}
