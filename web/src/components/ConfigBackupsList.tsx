import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { useConfigBackups, useRestoreBackup } from '@/hooks/useConfigEdit'

const MAXIMUM_LISTED_BACKUPS = 10

interface ConfigBackupsListProps {
  engineName: string
  fileName: string
  currentDigest: string
  onRestored: () => void
}

export function ConfigBackupsList({ engineName, fileName, currentDigest, onRestored }: ConfigBackupsListProps) {
  const { t, i18n } = useTranslation()
  const { data: backups, error } = useConfigBackups(engineName, fileName)
  const restore = useRestoreBackup()
  const [backupIdToRestore, setBackupIdToRestore] = useState<number | null>(null)
  const dateFormatter = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'medium' })
  if (error) {
    return <ErrorNotice error={error} />
  }
  if (!backups || backups.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('configEdit.backups.none')}</p>
  }
  return (
    <section aria-label={t('configEdit.backups.title')} className="space-y-2">
      <h3 className="text-sm font-medium">{t('configEdit.backups.title')}</h3>
      <ul className="space-y-1 text-sm">
        {backups.slice(0, MAXIMUM_LISTED_BACKUPS).map((backup) => (
          <li key={backup.id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <time dateTime={backup.created_at}>{dateFormatter.format(new Date(backup.created_at))}</time>
            <span>{backup.account_name}</span>
            <span>{t('configEdit.backups.size', { size: backup.size })}</span>
            <ConfirmActionDialog
              open={backupIdToRestore === backup.id}
              onOpenChange={(isOpen) => setBackupIdToRestore(isOpen ? backup.id : null)}
              trigger={
                <Button type="button" size="sm" variant="outline" aria-label={t('configEdit.backups.restoreAt', { date: dateFormatter.format(new Date(backup.created_at)) })}>
                  {t('configEdit.backups.restore')}
                </Button>
              }
              title={t('configEdit.backups.confirmTitle')}
              description={t('configEdit.backups.confirmBody')}
              submitLabel={t('configEdit.backups.restore')}
              request={() => restore.mutateAsync({ engineName, backupId: backup.id, expectedDigest: currentDigest })}
              onDone={() => {
                setBackupIdToRestore(null)
                onRestored()
              }}
              onFailed={() => setBackupIdToRestore(null)}
            />
          </li>
        ))}
      </ul>
      {restore.error && <ErrorNotice error={restore.error} />}
    </section>
  )
}
