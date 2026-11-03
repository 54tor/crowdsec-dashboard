import { useTranslation } from 'react-i18next'
import { ExportPanel } from '@/components/ExportPanel'
import { ImportPanel } from '@/components/ImportPanel'

export function ExportImport() {
  const { t } = useTranslation()
  return (
    <section className="space-y-6">
      <h1 className="text-xl font-semibold">{t('bundle.title')}</h1>
      <ExportPanel />
      <ImportPanel />
    </section>
  )
}
