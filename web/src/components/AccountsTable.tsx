import { useTranslation } from 'react-i18next'
import type { ManagedAccount } from '@/api/accountsApi'
import { AccountRoleCell, AccountRowActions } from '@/components/AccountRowActions'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { formatDateTime } from '@/lib/format'

interface AccountsTableProps {
  accounts: ManagedAccount[]
  onFailed: (failure: unknown) => void
  onSucceeded: () => void
}

export function AccountsTable({ accounts, onFailed, onSucceeded }: AccountsTableProps) {
  const { t, i18n } = useTranslation()
  const columns: DataTableColumn<ManagedAccount>[] = [
    { key: 'name', header: t('accounts.columns.name'), cell: (account) => account.account_name, mobile: 'primary' },
    { key: 'role', header: t('accounts.columns.role'), cell: (account) => <AccountRoleCell account={account} onFailed={onFailed} onSucceeded={onSucceeded} /> },
    { key: 'secondFactor', header: t('accounts.columns.secondFactor'), cell: (account) => t(account.second_factor_enrolled ? 'accounts.enrolled' : 'accounts.notEnrolled') },
    { key: 'locked', header: t('accounts.columns.locked'), cell: (account) => t(account.locked ? 'accounts.lockedYes' : 'accounts.lockedNo') },
    { key: 'createdAt', header: t('accounts.columns.createdAt'), cell: (account) => formatDateTime(account.created_at, i18n.language) },
    { key: 'actions', header: t('accounts.columns.actions'), cell: (account) => <AccountRowActions account={account} onFailed={onFailed} onSucceeded={onSucceeded} />, mobile: 'actions' },
  ]
  return (
    <DataTable
      caption={t('accounts.tableCaption')}
      columns={columns}
      rows={accounts}
      rowKey={(account) => account.account_name}
      cardsOnMobile
      emptyMessage={t('accounts.empty')}
    />
  )
}
