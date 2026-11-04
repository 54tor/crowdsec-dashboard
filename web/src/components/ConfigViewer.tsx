import { useTranslation } from 'react-i18next'
import { EmptyState } from '@/components/EmptyState'
import { ErrorNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useConfigFile } from '@/hooks/useReadResources'

export function ConfigViewer({ fileName }: { fileName: string | null }) {
  const { t } = useTranslation()
  const { data, error, isPending } = useConfigFile(fileName)
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
    <pre
      aria-label={t('config.viewer', { name: fileName })}
      tabIndex={0}
      className="max-h-[70vh] overflow-auto rounded-md border bg-secondary p-3 font-mono text-sm whitespace-pre focus-ring"
    >
      {data.content}
    </pre>
  )
}
