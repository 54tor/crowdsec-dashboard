import { useTranslation } from 'react-i18next'
import { EmptyState } from '@/components/EmptyState'
import { EngineTargetNote } from '@/components/EngineTargetNote'
import { ErrorNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useConfigFile } from '@/hooks/useReadResources'

interface ConfigViewerProps {
  engineName: string
  fileName: string | null
}

export function ConfigViewer({ engineName, fileName }: ConfigViewerProps) {
  const { t } = useTranslation()
  const { data, error, isPending } = useConfigFile(engineName, fileName)
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
    <div className="space-y-2">
      <EngineTargetNote engineName={engineName} />
      <pre
        aria-label={t('config.viewer', { name: fileName })}
        tabIndex={0}
        className="max-h-[70vh] overflow-auto rounded-md border bg-secondary p-3 font-mono text-sm whitespace-pre focus-ring"
      >
        {data.content}
      </pre>
    </div>
  )
}
