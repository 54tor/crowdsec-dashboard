import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { installHubItem, type HubItemKind } from '@/api/writeApi'
import { FormField } from '@/components/FormField'
import { HubKindSelect } from '@/components/HubKindSelect'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'
import { useHubMutation } from '@/hooks/useHubMutation'
import { validateHubName } from '@/lib/nameValidation'

interface HubInstallRequest {
  kind: HubItemKind
  name: string
}

const installRequested = ({ kind, name }: HubInstallRequest) => installHubItem(kind, name)

function AppSecHelp() {
  const { t } = useTranslation()
  return (
    <div className="space-y-2 text-sm text-muted-foreground">
      <p>{t('hub.appsecSuggestions')}</p>
      <p>{t('hub.appsecActivationNote')}</p>
    </div>
  )
}

function InstallForm({ onDone, onClose, reportPending }: { onDone: () => void; onClose: () => void; reportPending: (isPending: boolean) => void }) {
  const { t } = useTranslation()
  const [kind, setKind] = useState<HubItemKind>('collections')
  const [name, setName] = useState('')
  const installation = useHubMutation(installRequested, onDone)
  usePendingReport(installation.isPending, reportPending)
  const nameError = name === '' ? null : validateHubName(name)
  const isValid = name !== '' && !nameError

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (isValid && !installation.isPending) {
      installation.mutate({ kind, name })
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t('hub.installTitle')}</DialogTitle>
        <DialogDescription>{t('hub.installDescription')}</DialogDescription>
      </DialogHeader>
      <HubKindSelect value={kind} disabled={installation.isPending} onChange={setKind} />
      <FormField
        id="install-hub-item-name"
        label={t('hub.installName')}
        value={name}
        onChange={(changeEvent) => setName(changeEvent.target.value)}
        error={nameError && t(`errors.${nameError}`)}
      />
      <AppSecHelp />
      {installation.error && <ErrorNotice error={installation.error} />}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={installation.isPending} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" disabled={!isValid || installation.isPending}>
          {installation.isPending ? t('dialog.working') : t('hub.installSubmit')}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function InstallHubItemDialog() {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)
  return (
    <PendingLockDialog open={isOpen} onOpenChange={setIsOpen} trigger={<Button type="button">{t('hub.install')}</Button>}>
      {(reportPending) => <InstallForm onDone={() => setIsOpen(false)} onClose={() => setIsOpen(false)} reportPending={reportPending} />}
    </PendingLockDialog>
  )
}
