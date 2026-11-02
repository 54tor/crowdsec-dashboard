import { useTranslation } from 'react-i18next'
import { ACCOUNT_ROLES, type AccountRole } from '@/api/accountsApi'
import { TokenSelect } from '@/components/TokenSelect'

interface AccountRoleSelectProps {
  id: string
  label: string
  value: AccountRole
  onChange: (chosenRole: AccountRole) => void
  disabledReason?: string
}

export function AccountRoleSelect({ id, label, value, onChange, disabledReason }: AccountRoleSelectProps) {
  const { t } = useTranslation()
  return (
    <TokenSelect
      id={id}
      label={label}
      value={value}
      disabled={disabledReason !== undefined}
      title={disabledReason}
      onChange={(chosenRole) => onChange(chosenRole as AccountRole)}
      options={ACCOUNT_ROLES.map((role) => ({ value: role, label: t(`accounts.roles.${role}`) }))}
    />
  )
}
