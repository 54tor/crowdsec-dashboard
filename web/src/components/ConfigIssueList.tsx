import { useTranslation } from 'react-i18next'
import type { ConfigIssue } from '@/api/configEditApi'
import { Badge } from '@/components/ui/badge'

interface ConfigIssueListProps {
  issues: ConfigIssue[] | null
}

export function ConfigIssueList({ issues }: ConfigIssueListProps) {
  const { t } = useTranslation()
  return (
    <div aria-live="polite" aria-label={t('configEdit.issues.title')}>
      {issues !== null && issues.length === 0 && <p className="text-sm text-nominal">{t('configEdit.issues.none')}</p>}
      {issues !== null && issues.length > 0 && (
        <ul className="space-y-1 text-sm">
          {issues.map((issue) => (
            <li key={`${issue.line}-${issue.path}-${issue.code}`} className="flex flex-wrap items-baseline gap-2">
              <Badge variant={issue.severity === 'error' ? 'critical' : 'warning'}>{t(`configEdit.issues.severity.${issue.severity}`)}</Badge>
              <span>{t('configEdit.issues.line', { line: issue.line })}</span>
              {issue.path !== '' && <code className="font-mono break-all">{issue.path}</code>}
              <span>{t(`configEdit.issues.codes.${issue.code}`, { defaultValue: issue.code })}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
