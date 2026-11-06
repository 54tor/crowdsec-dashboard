import { useTranslation } from 'react-i18next'
import { failureCodeOf, failureDetailsOf } from '@/api/configEditApi'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { ConfigIssueList } from '@/components/ConfigIssueList'
import { Button } from '@/components/ui/button'

const SECRET_MERGE_CODES = ['redacted_content', 'secret_context_changed', 'merged_structure_changed']

interface ConfigEditFailureProps {
  failure: unknown
  onReloadFile: () => void
}

export function ConfigEditFailure({ failure, onReloadFile }: ConfigEditFailureProps) {
  const { t } = useTranslation()
  const code = failureCodeOf(failure)
  const details = failureDetailsOf(failure)
  if (code === 'digest_mismatch') {
    return (
      <WarningNotice title={t('configEdit.conflict.title')}>
        <p>{t('configEdit.conflict.body')}</p>
        <Button type="button" size="sm" variant="outline" className="mt-2" onClick={onReloadFile}>
          {t('configEdit.conflict.reload')}
        </Button>
      </WarningNotice>
    )
  }
  if (code === 'config_test_failed') {
    return <ErrorNotice error={failure} message={details.rolledBack ? t('configEdit.rejectedRolledBack') : t('configEdit.rejected')} />
  }
  if (code === 'config_inconsistent') {
    return (
      <div className="space-y-1">
        <ErrorNotice error={failure} />
        <ul className="list-disc pl-6 font-mono text-sm break-all">
          {details.affectedFiles.map((affectedFile) => (
            <li key={affectedFile}>{affectedFile}</li>
          ))}
        </ul>
      </div>
    )
  }
  if (code === 'schema_invalid') {
    return (
      <div className="space-y-1">
        <ErrorNotice error={failure} message={t('configEdit.schemaInvalid')} />
        <ConfigIssueList issues={details.issues ?? []} />
      </div>
    )
  }
  if (SECRET_MERGE_CODES.includes(code)) {
    return (
      <ErrorNotice
        error={failure}
        message={`${details.line === undefined ? '' : `${t('configEdit.issues.line', { line: details.line })}. `}${t(`errors.${code}`)} ${t('configEdit.secretExplanation')}`}
      />
    )
  }
  return <ErrorNotice error={failure} />
}
