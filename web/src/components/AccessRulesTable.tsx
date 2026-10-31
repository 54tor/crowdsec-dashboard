import { useTranslation } from 'react-i18next'
import { ACCESS_RULES_QUERY_KEY, deleteAccessRule, type AccessRule } from '@/api/accessRulesApi'
import { DataTable } from '@/components/DataTable'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { countryLabel } from '@/lib/countryLabel'

interface AccessRulesTableProps {
  rules: AccessRule[]
  onRuleDeleted: () => void
}

export function AccessRulesTable({ rules, onRuleDeleted }: AccessRulesTableProps) {
  const { t, i18n } = useTranslation()
  const columns = [
    { key: 'kind', header: t('accountSecurity.columns.kind'), cell: (rule: AccessRule) => (rule.kind === 'ip' || rule.kind === 'country' ? t(`accountSecurity.kinds.${rule.kind}`) : rule.kind) },
    { key: 'value', header: t('accountSecurity.columns.value'), cell: (rule: AccessRule) => (rule.kind === 'country' ? countryLabel(rule.value, i18n.language) : rule.value) },
    {
      key: 'actions',
      header: t('accountSecurity.columns.actions'),
      cell: (rule: AccessRule) => (
        <RowDeleteAction
          buttonLabel={t('common.delete')}
          ariaLabel={t('accountSecurity.deleteAria', { value: rule.value })}
          title={t('accountSecurity.deleteTitle')}
          description={t(rules.length === 1 ? 'accountSecurity.deleteLastDescription' : 'accountSecurity.deleteDescription')}
          target={rule.value}
          request={() => deleteAccessRule(rule.id)}
          invalidates={[ACCESS_RULES_QUERY_KEY]}
          onDeleted={onRuleDeleted}
        />
      ),
    },
  ]
  return <DataTable caption={t('accountSecurity.tableCaption')} columns={columns} rows={rules} rowKey={(rule) => rule.id} />
}
