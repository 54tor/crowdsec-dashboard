import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ConfigViewer } from '@/components/ConfigViewer'
import { EmptyState } from '@/components/EmptyState'
import { EngineTargetSelect } from '@/components/EngineTargetSelect'
import { PageHeader } from '@/components/PageHeader'
import { ErrorNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { Button } from '@/components/ui/button'
import { useEngineTarget } from '@/hooks/useEngineTarget'
import { useConfigFiles } from '@/hooks/useReadResources'

interface FileSelection {
  engineName: string
  fileName: string
}

export function Config() {
  const { t } = useTranslation()
  const [engineName, setEngineName] = useEngineTarget()
  const { data, error, isPending } = useConfigFiles(engineName)
  const [fileSelection, setFileSelection] = useState<FileSelection | null>(null)
  const isSelectionOfThisEngine = fileSelection?.engineName === engineName
  const selectedFile = isSelectionOfThisEngine ? fileSelection.fileName : null
  return (
    <section className="space-y-4">
      <PageHeader title={t('config.title')} description={t('config.filesNote')} />
      <EngineTargetSelect id="config-engine" value={engineName} onChange={setEngineName} />
      <p className="text-sm text-muted-foreground">{t('config.redactionNote')}</p>
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {data && (
        <div className="grid gap-4 md:grid-cols-[16rem_1fr]">
          <nav aria-label={t('config.files')}>
            {data.files.length === 0 ? (
              <EmptyState message={t('config.noFiles')} />
            ) : (
              <ul className="space-y-1">
                {data.files.map((fileName) => (
                  <li key={fileName}>
                    <Button
                      variant={fileName === selectedFile ? 'outline' : 'ghost'}
                      size="sm"
                      aria-pressed={fileName === selectedFile}
                      className="w-full justify-start font-mono break-all"
                      onClick={() => setFileSelection({ engineName, fileName })}
                    >
                      {fileName}
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </nav>
          <ConfigViewer engineName={engineName} fileName={selectedFile} />
        </div>
      )}
    </section>
  )
}
