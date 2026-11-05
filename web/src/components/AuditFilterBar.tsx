import { useTranslation } from 'react-i18next'
import type { AuditFilters } from '@/api/auditApi'
import { FormField } from '@/components/FormField'
import { SearchFilterField } from '@/components/SearchFilterField'
import type { AuditFilterErrors } from '@/lib/auditFilterValidation'

interface AuditFilterBarProps {
  values: AuditFilters
  errors: AuditFilterErrors
  onChange: (filterName: keyof AuditFilters, value: string) => void
}

const AUDIT_FIELD_MAXIMUM_LENGTH = 64

export function AuditFilterBar({ values, errors, onChange }: AuditFilterBarProps) {
  const { t } = useTranslation()
  const errorMessage = (filterName: keyof AuditFilters) => {
    const errorKey = errors[filterName]
    if (!errorKey) {
      return null
    }
    const isAuditSpecificError = errorKey === 'actionInvalid' || errorKey === 'accountInvalid'
    return isAuditSpecificError ? t(`audit.filters.${errorKey}`) : t(`filters.${errorKey}`)
  }

  return (
    <form role="search" aria-label={t('filters.label')} onSubmit={(submitEvent) => submitEvent.preventDefault()} className="grid gap-3 sm:grid-cols-4">
      <SearchFilterField value={values.q} error={errorMessage('q')} hint={t('audit.filters.qHint')} onChange={(searchTerm) => onChange('q', searchTerm)} />
      <FormField
        id="audit-filter-action"
        label={t('audit.filters.action')}
        hint={t('audit.filters.actionHint')}
        value={values.action}
        onChange={(changeEvent) => onChange('action', changeEvent.target.value)}
        error={errorMessage('action')}
        maxLength={AUDIT_FIELD_MAXIMUM_LENGTH}
      />
      <FormField
        id="audit-filter-account"
        label={t('audit.filters.account')}
        value={values.account}
        onChange={(changeEvent) => onChange('account', changeEvent.target.value)}
        error={errorMessage('account')}
        maxLength={AUDIT_FIELD_MAXIMUM_LENGTH}
      />
      <FormField
        id="audit-filter-since"
        label={t('filters.since')}
        value={values.since}
        onChange={(changeEvent) => onChange('since', changeEvent.target.value)}
        placeholder={t('filters.sincePlaceholder')}
        error={errorMessage('since')}
        maxLength={AUDIT_FIELD_MAXIMUM_LENGTH}
      />
    </form>
  )
}
