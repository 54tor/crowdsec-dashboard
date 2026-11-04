import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '@/api/client'
import type { AlertDetail, AlertEvent } from '@/api/types'
import { AppSecSummary } from '@/components/AppSecSummary'
import { EventMetaList } from '@/components/EventMetaList'
import { Icon } from '@/components/Icon'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { UntrustedText } from '@/components/UntrustedText'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { formatDateTime } from '@/lib/format'

interface AlertDetailDialogProps {
  archiveId: number
  alertId: number
  engineName: string
}

function AlertEventItem({ alertEvent }: { alertEvent: AlertEvent }) {
  const { t, i18n } = useTranslation()
  return (
    <li className="space-y-1 rounded-lg border p-3">
      <p className="text-xs text-muted-foreground">{t('alertDetail.eventAt', { date: formatDateTime(alertEvent.timestamp, i18n.language) })}</p>
      <EventMetaList meta={alertEvent.meta} />
    </li>
  )
}

function AlertDetailBody({ archiveId }: { archiveId: number }) {
  const { t } = useTranslation()
  const detailQuery = useQuery({
    queryKey: ['alert-detail', archiveId],
    queryFn: () => apiFetch<AlertDetail>(`/api/alerts/archive/${archiveId}`),
  })
  if (detailQuery.error) {
    return <ErrorNotice error={detailQuery.error} />
  }
  if (!detailQuery.data) {
    return <TableSkeleton />
  }
  const alertDetail = detailQuery.data
  return (
    <div className="max-h-[60vh] space-y-3 overflow-y-auto">
      <p className="text-sm">
        <UntrustedText value={alertDetail.message} />
      </p>
      {alertDetail.events_truncated && <WarningNotice>{t('alertDetail.truncated')}</WarningNotice>}
      {alertDetail.source_kind === 'appsec' && <AppSecSummary events={alertDetail.events} />}
      <h3 className="text-sm font-medium">{t('alertDetail.events')}</h3>
      {alertDetail.events.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('alertDetail.noEvents')}</p>
      ) : (
        <ol className="space-y-2">
          {alertDetail.events.map((alertEvent, eventPosition) => (
            <AlertEventItem key={eventPosition} alertEvent={alertEvent} />
          ))}
        </ol>
      )}
    </div>
  )
}

export function AlertDetailDialog({ archiveId, alertId, engineName }: AlertDetailDialogProps) {
  const { t } = useTranslation()
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button type="button" variant="outline" size="icon" aria-label={t('alerts.detailsAria', { id: alertId, engine: engineName })} title={t('alerts.details')}>
          <Icon name="visibility" />
        </Button>
      </DialogTrigger>
      <DialogContent showCloseButton={false} className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('alertDetail.title', { id: alertId, engine: engineName })}</DialogTitle>
          <DialogDescription>{t('alertDetail.description')}</DialogDescription>
        </DialogHeader>
        <AlertDetailBody archiveId={archiveId} />
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline">
              {t('alertDetail.close')}
            </Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
