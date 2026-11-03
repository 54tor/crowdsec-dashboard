import { useTranslation } from 'react-i18next'
import type { BundleSection, ImportPlan } from '@/api/bundleApi'
import { AllowlistNotice, BundleWarnings, UnavailableSections } from '@/components/BundleWarnings'
import { translateBundleCode } from '@/lib/bundleCodes'

function plannedCount(plan: ImportPlan, sectionName: BundleSection): number {
  if (sectionName === 'config') {
    return plan.config.filter((fileAction) => fileAction.change !== 'unchanged').length
  }
  return plan[sectionName].length
}

function skippedCount(plan: ImportPlan, sectionName: BundleSection): number {
  return Object.values(plan.skipped_counts[sectionName] ?? {}).reduce((total, reasonCount) => total + reasonCount, 0)
}

function SkippedReasons({ plan, sectionName }: { plan: ImportPlan; sectionName: BundleSection }) {
  const { t } = useTranslation()
  const reasonCounts = Object.entries(plan.skipped_counts[sectionName] ?? {})
  return (
    <ul>
      {reasonCounts.map(([reason, reasonCount]) => (
        <li key={reason}>
          {translateBundleCode(t, 'skipReasons', reason)} ({reasonCount})
        </li>
      ))}
    </ul>
  )
}

export function ImportPlanSummary({ plan }: { plan: ImportPlan }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-3">
      <table className="w-full text-sm">
        <caption className="text-left text-base font-medium">{t('bundle.summaryCaption')}</caption>
        <thead>
          <tr className="text-left">
            <th scope="col">{t('bundle.columns.section')}</th>
            <th scope="col">{t('bundle.columns.planned')}</th>
            <th scope="col">{t('bundle.columns.skipped')}</th>
            <th scope="col">{t('bundle.columns.state')}</th>
          </tr>
        </thead>
        <tbody>
          {plan.sections.map((sectionName) => {
            const isUnavailable = plan.unavailable.includes(sectionName)
            return (
              <tr key={sectionName}>
                <th scope="row" className="text-left font-normal">
                  {t(`bundle.sections.${sectionName}`)}
                </th>
                <td>{isUnavailable ? '—' : plannedCount(plan, sectionName)}</td>
                <td>
                  {isUnavailable ? '—' : skippedCount(plan, sectionName)}
                  {!isUnavailable && <SkippedReasons plan={plan} sectionName={sectionName} />}
                </td>
                <td>{isUnavailable ? translateBundleCode(t, 'problems', plan.unavailable_codes[sectionName] ?? 'section_unavailable') : t('bundle.ready')}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
      <UnavailableSections sections={plan.unavailable} codes={plan.unavailable_codes} />
      <AllowlistNotice counts={plan.skipped_counts} />
      <BundleWarnings warnings={plan.warnings} />
    </div>
  )
}
