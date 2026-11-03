import { Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { updateHub, upgradeHub } from '@/api/writeApi'
import { InstallHubItemDialog } from '@/components/InstallHubItemDialog'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { useHubMutation } from '@/hooks/useHubMutation'

export function HubToolbar() {
  const { t } = useTranslation()
  const update = useHubMutation(updateHub)
  const upgrade = useHubMutation(upgradeHub)
  const isBusy = update.isPending || upgrade.isPending
  const failure = update.error ?? upgrade.error

  function labelOf(isPending: boolean, idleLabel: string) {
    return (
      <>
        {isPending && <Loader2 aria-hidden="true" className="animate-spin" />}
        {isPending ? t('dialog.working') : idleLabel}
      </>
    )
  }

  return (
    <div className="space-y-2" aria-busy={isBusy}>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" disabled={isBusy} onClick={() => update.mutate()}>
          {labelOf(update.isPending, t('hub.update'))}
        </Button>
        <Button type="button" variant="outline" disabled={isBusy} onClick={() => upgrade.mutate()}>
          {labelOf(upgrade.isPending, t('hub.upgrade'))}
        </Button>
        <InstallHubItemDialog />
      </div>
      <p className="text-sm text-muted-foreground">{t('hub.slowNote')}</p>
      {failure && <ErrorNotice error={failure} />}
    </div>
  )
}
