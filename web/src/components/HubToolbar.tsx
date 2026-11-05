import { useTranslation } from 'react-i18next'
import { updateHub, upgradeHub } from '@/api/writeApi'
import { Icon } from '@/components/Icon'
import { InstallHubItemDialog } from '@/components/InstallHubItemDialog'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { useHubMutation } from '@/hooks/useHubMutation'

export function HubToolbar({ engineName }: { engineName: string }) {
  const { t } = useTranslation()
  const update = useHubMutation(engineName, () => updateHub(engineName))
  const upgrade = useHubMutation(engineName, () => upgradeHub(engineName))
  const isBusy = update.isPending || upgrade.isPending
  const failure = update.error ?? upgrade.error

  function labelOf(isPending: boolean, idleLabel: string) {
    return (
      <>
        {isPending && <Icon name="progress_activity" className="size-4 motion-safe:animate-spin" />}
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
        <InstallHubItemDialog engineName={engineName} />
      </div>
      <p className="text-sm text-muted-foreground">{t('hub.slowNote')}</p>
      {failure && <ErrorNotice error={failure} />}
    </div>
  )
}
