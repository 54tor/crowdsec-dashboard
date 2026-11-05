import { useTranslation } from 'react-i18next'
import type { Alert } from '@/api/types'
import { deleteAlert } from '@/api/writeApi'
import { AlertDetailDialog } from '@/components/AlertDetailDialog'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { useCanWrite } from '@/hooks/useCanWrite'
import { useIsWritableEngine } from '@/hooks/useEngineTarget'
import { engineOfRow, isRowWritableOnItsEngine } from '@/lib/liveRow'

export function AlertRowActions({ alertRow }: { alertRow: Alert }) {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const isWritableEngine = useIsWritableEngine()
  const engineName = engineOfRow(alertRow)
  return (
    <div className="flex flex-nowrap items-center gap-1">
      {alertRow.archive_id !== null && <AlertDetailDialog archiveId={alertRow.archive_id} alertId={alertRow.id} engineName={alertRow.engine} />}
      {canWrite && isRowWritableOnItsEngine(alertRow, isWritableEngine) && (
        <RowDeleteAction
          buttonLabel={t('alerts.delete')}
          ariaLabel={t('alerts.deleteAria', { id: alertRow.id })}
          title={t('alerts.deleteTitle', { id: alertRow.id })}
          description={t('alerts.deleteDescription', { id: alertRow.id })}
          target={String(alertRow.id)}
          engineName={engineName}
          request={(confirm) => deleteAlert(String(alertRow.id), alertRow.uuid ?? '', confirm, engineName)}
          invalidates={[['alerts'], ['decisions']]}
          iconOnly
        />
      )}
    </div>
  )
}
