import { useTranslation } from 'react-i18next'
import { InfoNotice, WarningNotice } from '@/components/Notice'
import { UntrustedText } from '@/components/UntrustedText'
import { splitWarning, translateBundleCode } from '@/lib/bundleCodes'

export function BundleWarnings({ warnings }: { warnings: readonly string[] }) {
  const { t } = useTranslation()
  if (warnings.length === 0) {
    return null
  }
  return (
    <WarningNotice title={t('bundle.warningsTitle')}>
      <ul className="list-disc pl-4">
        {warnings.map((warning) => {
          const { code, detail } = splitWarning(warning)
          return (
            <li key={warning}>
              {t(`bundle.warnings.${code}`, { defaultValue: t('bundle.unknownCode', { code }) })}
              {detail !== '' && (
                <>
                  {' '}
                  <UntrustedText value={detail} />
                </>
              )}
            </li>
          )
        })}
      </ul>
    </WarningNotice>
  )
}

export function UnavailableSections({ sections, codes }: { sections: readonly string[]; codes: Record<string, string> }) {
  const { t } = useTranslation()
  if (sections.length === 0) {
    return null
  }
  return (
    <WarningNotice title={t('bundle.unavailableTitle')}>
      <p>{t('bundle.unavailableHint')}</p>
      <ul className="list-disc pl-4">
        {sections.map((sectionName) => (
          <li key={sectionName}>
            {t('bundle.sectionLine', { section: t(`bundle.sections.${sectionName}`), state: translateBundleCode(t, 'problems', codes[sectionName] ?? 'section_unavailable') })}
          </li>
        ))}
      </ul>
      {codes.config === 'import_disabled' && <p className="mt-2">{t('bundle.importDisabledHelp')}</p>}
    </WarningNotice>
  )
}

export function AllowlistNotice({ counts }: { counts: Record<string, Record<string, number>> }) {
  const { t } = useTranslation()
  const allReasonCounts = Object.values(counts)
  const allowlistedCount = allReasonCounts.reduce((total, reasonCounts) => total + (reasonCounts.allowlisted ?? 0), 0)
  const unavailableCount = allReasonCounts.reduce((total, reasonCounts) => total + (reasonCounts.allowlist_unavailable ?? 0), 0)
  return (
    <>
      {allowlistedCount > 0 && <InfoNotice>{t('bundle.allowlistedNotice', { count: allowlistedCount })}</InfoNotice>}
      {unavailableCount > 0 && <WarningNotice>{t('bundle.allowlistUnavailableNotice', { count: unavailableCount })}</WarningNotice>}
    </>
  )
}
