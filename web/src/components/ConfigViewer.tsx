import { useTranslation } from 'react-i18next'
import { ErrorNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useConfigFile } from '@/hooks/useReadResources'

export function ConfigViewer({ fileName }: { fileName: string | null }) {
  const { t } = useTranslation()
  const { data, error, isPending } = useConfigFile(fileName)
  if (fileName === null) {
    return <p className="text-sm text-muted-foreground">{t('config.select')}</p>
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
      className="max-h-[70vh] overflow-auto rounded-lg border bg-muted p-3 font-mono text-sm whitespace-pre outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      {data.content}
    </pre>
  )
}
