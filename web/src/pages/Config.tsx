import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ConfigViewer } from '@/components/ConfigViewer'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { ErrorNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { Button } from '@/components/ui/button'
import { useConfigFiles } from '@/hooks/useReadResources'

export function Config() {
  const { t } = useTranslation()
  const { data, error, isPending } = useConfigFiles()
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  return (
    <section className="space-y-4">
      <PageHeader title={t('config.title')} description={t('config.filesNote')} />
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
                      onClick={() => setSelectedFile(fileName)}
                    >
                      {fileName}
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </nav>
          <ConfigViewer fileName={selectedFile} />
        </div>
      )}
    </section>
  )
}
