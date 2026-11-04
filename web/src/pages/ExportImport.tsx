import { useTranslation } from 'react-i18next'
import { ExportPanel } from '@/components/ExportPanel'
import { PageHeader } from '@/components/PageHeader'
import { ImportPanel } from '@/components/ImportPanel'

export function ExportImport() {
  const { t } = useTranslation()
  return (
    <section className="space-y-6">
      <PageHeader title={t('bundle.title')} />
      <ExportPanel />
      <ImportPanel />
    </section>
  )
}
