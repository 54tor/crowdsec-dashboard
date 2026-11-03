import { useTranslation } from 'react-i18next'
import type { SectionReport } from '@/api/bundleApi'
import { BundleWarnings } from '@/components/BundleWarnings'
import { UntrustedText } from '@/components/UntrustedText'
import { translateBundleCode } from '@/lib/bundleCodes'

function SectionResult({ sectionReport }: { sectionReport: SectionReport }) {
  const { t } = useTranslation()
  const skippedReasons = Object.entries(sectionReport.skipped_reasons ?? {})
  return (
    <li className="space-y-1 rounded border p-2">
      <p className="font-medium">
        {t(`bundle.sections.${sectionReport.section}`)} : {translateBundleCode(t, 'status', sectionReport.status)}
      </p>
      <p className="text-sm">{t('bundle.resultCounts', { applied: sectionReport.applied, skipped: sectionReport.skipped, failed: sectionReport.failed })}</p>
      {skippedReasons.length > 0 && (
        <ul className="list-disc pl-4 text-sm">
          {skippedReasons.map(([reason, reasonCount]) => (
            <li key={reason}>
              {translateBundleCode(t, 'skipReasons', reason)} ({reasonCount})
            </li>
          ))}
        </ul>
      )}
      {sectionReport.error_code && <p className="text-sm text-destructive">{translateBundleCode(t, 'problems', sectionReport.error_code)}</p>}
      {(sectionReport.affected_files?.length ?? 0) > 0 && (
        <div className="text-sm">
          <p>{t('bundle.affectedFiles')}</p>
          <ul className="list-disc pl-4">
            {sectionReport.affected_files?.map((fileName) => (
              <li key={fileName}>
                <UntrustedText value={fileName} />
              </li>
            ))}
          </ul>
        </div>
      )}
      <BundleWarnings warnings={sectionReport.warnings ?? []} />
    </li>
  )
}

export function ImportReport({ sections }: { sections: readonly SectionReport[] }) {
  const { t } = useTranslation()
  return (
    <section className="space-y-2" aria-labelledby="import-report-heading">
      <h3 id="import-report-heading" className="text-base font-medium">
        {t('bundle.resultTitle')}
      </h3>
      <ul className="space-y-2">
        {sections.map((sectionReport) => (
          <SectionResult key={sectionReport.section} sectionReport={sectionReport} />
        ))}
      </ul>
    </section>
  )
}
