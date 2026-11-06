import { useTranslation } from 'react-i18next'
import { OVERRIDES_FILE_NAME } from '@/api/configEditApi'
import { ConfigBackupsList } from '@/components/ConfigBackupsList'
import { ConfigRawEditor } from '@/components/ConfigRawEditor'
import { ConfigReadOnlyFile } from '@/components/ConfigReadOnlyFile'
import { EmptyState } from '@/components/EmptyState'
import { ErrorNotice } from '@/components/Notice'
import { ReloadBanner } from '@/components/ReloadBanner'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useConfigEditFile } from '@/hooks/useConfigEdit'

interface ConfigAdvancedEditorProps {
  engineName: string
  fileName: string | null
  onSelectFile: (fileName: string) => void
  onDirtyChange: (isDirty: boolean) => void
  onDeleted: () => void
}

export function ConfigAdvancedEditor({ engineName, fileName, onSelectFile, onDirtyChange, onDeleted }: ConfigAdvancedEditorProps) {
  const { t } = useTranslation()
  const { data: file, error, isPending, refetch } = useConfigEditFile(engineName, fileName)
  if (fileName === null) {
    return <EmptyState message={t('config.select')} />
  }
  if (error) {
    return <ErrorNotice error={error} />
  }
  if (isPending) {
    return <TableSkeleton />
  }
  return (
    <div className="min-w-0 space-y-4">
      <ReloadBanner engineName={engineName} />
      {file.read_only ? (
        <ConfigReadOnlyFile file={file} onEditOverrides={() => onSelectFile(OVERRIDES_FILE_NAME)} />
      ) : (
        <ConfigRawEditor
          key={`${engineName}|${file.name}|${file.digest}`}
          engineName={engineName}
          file={file}
          onDirtyChange={onDirtyChange}
          onReloadFile={() => void refetch()}
          onDeleted={onDeleted}
        />
      )}
      {file.exists && !file.read_only && (
        <ConfigBackupsList engineName={engineName} fileName={file.name} currentDigest={file.digest} onRestored={() => void refetch()} />
      )}
    </div>
  )
}
