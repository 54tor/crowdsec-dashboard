import { useTranslation } from 'react-i18next'
import { IMPORT_CONFIRMATION } from '@/api/bundleApi'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { ImportPlanDetails } from '@/components/ImportPlanDetails'
import { ImportPlanSummary } from '@/components/ImportPlanSummary'
import { ImportReport } from '@/components/ImportReport'
import { SectionPicker } from '@/components/SectionPicker'
import { TypedConfirmDialog } from '@/components/TypedConfirmDialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useBundleImport } from '@/hooks/useBundleImport'

export function ImportPanel() {
  const { t } = useTranslation()
  const bundleImport = useBundleImport()
  const { plan, phase, selectedSections } = bundleImport
  const hasUnavailableSection = plan !== null && plan.unavailable.length > 0
  const canApply = plan !== null && !hasUnavailableSection && plan.sections.length > 0

  return (
    <section className="space-y-3 bg-card border rounded-md p-4" aria-labelledby="import-heading">
      <h2 id="import-heading" className="text-base font-medium">
        {t('bundle.importTitle')}
      </h2>
      <div className="space-y-1">
        <Label htmlFor="import-file">{t('bundle.fileLabel')}</Label>
        <Input
          id="import-file"
          type="file"
          accept="application/json,.json"
          disabled={phase !== 'idle'}
          onChange={(changeEvent) => {
            const chosenFile = changeEvent.target.files?.[0]
            if (chosenFile) {
              void bundleImport.loadFile(chosenFile)
            }
          }}
        />
      </div>
      {bundleImport.fileErrorCode && <ErrorNotice error={{ code: bundleImport.fileErrorCode }} />}
      {bundleImport.bundle !== null && (
        <>
          <SectionPicker
            idPrefix="import-section"
            sections={bundleImport.availableSections}
            selected={selectedSections}
            disabled={phase !== 'idle'}
            onToggle={bundleImport.toggleSection}
          />
          <div className="flex flex-wrap gap-2">
            <Button type="button" disabled={phase !== 'idle' || selectedSections.length === 0} onClick={() => void bundleImport.preview()}>
              {phase === 'previewing' ? t('dialog.working') : t('bundle.previewButton')}
            </Button>
            <Button type="button" variant="outline" disabled={phase !== 'idle'} onClick={bundleImport.reset}>
              {t('bundle.resetButton')}
            </Button>
          </div>
        </>
      )}
      {bundleImport.failure !== null && <ErrorNotice error={bundleImport.failure} />}
      {plan !== null && (
        <>
          <ImportPlanSummary plan={plan} />
          <ImportPlanDetails plan={plan} />
          {hasUnavailableSection && <WarningNotice>{t('bundle.deselectUnavailable')}</WarningNotice>}
          <TypedConfirmDialog
            idPrefix="import-apply"
            trigger={<Button type="button" disabled={!canApply || phase !== 'idle'}>{t('bundle.applyButton')}</Button>}
            title={t('bundle.applyDialogTitle')}
            description={t('bundle.applyDialogDescription')}
            confirmWord={IMPORT_CONFIRMATION}
            submitLabel={t('bundle.applyButton')}
            isRunning={phase === 'applying'}
            run={() => bundleImport.apply()}
          />
        </>
      )}
      {bundleImport.applyResponse !== null && <ImportReport sections={bundleImport.applyResponse.report.sections} />}
    </section>
  )
}
