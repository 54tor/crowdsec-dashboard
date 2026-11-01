import { useTranslation } from 'react-i18next'
import type { Alert } from '@/api/types'
import { deleteAlert } from '@/api/writeApi'
import { AlertDetailDialog } from '@/components/AlertDetailDialog'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { isLiveLocalRow } from '@/lib/liveRow'

export function AlertRowActions({ alertRow }: { alertRow: Alert }) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap gap-2">
      {alertRow.archive_id !== null && <AlertDetailDialog archiveId={alertRow.archive_id} alertId={alertRow.id} engineName={alertRow.engine} />}
      {isLiveLocalRow(alertRow) && (
        <RowDeleteAction
          buttonLabel={t('alerts.delete')}
          ariaLabel={t('alerts.deleteAria', { id: alertRow.id })}
          title={t('alerts.deleteTitle', { id: alertRow.id })}
          description={t('alerts.deleteDescription', { id: alertRow.id })}
          target={String(alertRow.id)}
          request={(confirm) => deleteAlert(String(alertRow.id), alertRow.uuid ?? '', confirm)}
          invalidates={[['alerts'], ['decisions']]}
        />
      )}
    </div>
  )
}
