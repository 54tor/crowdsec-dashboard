import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { reloadCrowdsec } from '@/api/writeApi'
import { Icon } from '@/components/Icon'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { useReloadRequired } from '@/hooks/useReloadRequired'

export function ReloadBanner() {
  const { t } = useTranslation()
  const { isReloadRequired, clearReloadRequired } = useReloadRequired()
  const reload = useMutation({ mutationFn: reloadCrowdsec, onSuccess: clearReloadRequired })
  if (!isReloadRequired) {
    return null
  }
  return (
    <div className="space-y-2">
      <WarningNotice title={t('hub.reloadRequired')}>
        <p>{t('hub.reloadHint')}</p>
        <Button type="button" size="sm" className="mt-2" disabled={reload.isPending} onClick={() => reload.mutate()}>
          {reload.isPending && <Icon name="progress_activity" className="size-4 motion-safe:animate-spin" />}
          {reload.isPending ? t('dialog.working') : t('hub.reload')}
        </Button>
      </WarningNotice>
      {reload.error && <ErrorNotice error={reload.error} />}
    </div>
  )
}
