import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { BUNDLE_SECTIONS, SECRETS_CONFIRMATION, exportBundle, type BundleSection } from '@/api/bundleApi'
import { CheckboxField } from '@/components/CheckboxField'
import { ErrorNotice, InfoNotice, WarningNotice } from '@/components/Notice'
import { SectionPicker } from '@/components/SectionPicker'
import { TypedConfirmDialog } from '@/components/TypedConfirmDialog'
import { Button } from '@/components/ui/button'
import { downloadBlob } from '@/lib/downloadBlob'

export function ExportPanel() {
  const { t } = useTranslation()
  const [selectedSections, setSelectedSections] = useState<BundleSection[]>([...BUNDLE_SECTIONS])
  const [includeSecrets, setIncludeSecrets] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [failure, setFailure] = useState<unknown>(null)
  const [skippedAlerts, setSkippedAlerts] = useState(0)

  function toggleSection(sectionName: BundleSection) {
    setSelectedSections((previous) => (previous.includes(sectionName) ? previous.filter((name) => name !== sectionName) : [...previous, sectionName]))
  }

  async function runExport(typedWord: string) {
    setIsExporting(true)
    setFailure(null)
    setSkippedAlerts(0)
    try {
      const exported = await exportBundle({ sections: selectedSections, includeSecrets, confirmSecrets: typedWord })
      downloadBlob(exported.blob, exported.fileName)
      setSkippedAlerts(exported.skippedAlerts)
    } catch (exportFailure) {
      setFailure(exportFailure)
    } finally {
      setIsExporting(false)
    }
  }

  const hasNoSection = selectedSections.length === 0
  return (
    <section className="space-y-3" aria-labelledby="export-heading">
      <h2 id="export-heading" className="text-base font-medium">
        {t('bundle.exportTitle')}
      </h2>
      <SectionPicker idPrefix="export-section" sections={BUNDLE_SECTIONS} selected={selectedSections} disabled={isExporting} onToggle={toggleSection} />
      <CheckboxField id="export-secrets" label={t('bundle.includeSecrets')} checked={includeSecrets} onChange={setIncludeSecrets} />
      {includeSecrets && <WarningNotice title={t('bundle.secretsWarningTitle')}>{t('bundle.secretsWarning')}</WarningNotice>}
      {includeSecrets ? (
        <TypedConfirmDialog
          idPrefix="export-secrets-dialog"
          trigger={<Button type="button" disabled={hasNoSection || isExporting}>{t('bundle.exportButton')}</Button>}
          title={t('bundle.secretsDialogTitle')}
          description={t('bundle.secretsDialogDescription')}
          confirmWord={SECRETS_CONFIRMATION}
          submitLabel={t('bundle.exportButton')}
          isRunning={isExporting}
          run={runExport}
        />
      ) : (
        <Button type="button" disabled={hasNoSection || isExporting} onClick={() => void runExport('')}>
          {isExporting ? t('dialog.working') : t('bundle.exportButton')}
        </Button>
      )}
      {failure !== null && <ErrorNotice error={failure} />}
      {skippedAlerts > 0 && <InfoNotice>{t('bundle.skippedAlerts', { count: skippedAlerts })}</InfoNotice>}
    </section>
  )
}
