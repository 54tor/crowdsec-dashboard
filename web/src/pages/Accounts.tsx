import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ACCOUNTS_QUERY_KEY, listAccounts, type ManagedAccount } from '@/api/accountsApi'
import { AccountsTable } from '@/components/AccountsTable'
import { ClientFilterField } from '@/components/ClientFilterField'
import { ClientFilterResults } from '@/components/ClientFilterResults'
import { CreateAccountDialog } from '@/components/CreateAccountDialog'
import { DensityToggle } from '@/components/DensityToggle'
import { ErrorNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useClientFilter } from '@/hooks/useClientFilter'
import { formatDateTime } from '@/lib/format'

const NO_ACCOUNTS: ManagedAccount[] = []

export function Accounts() {
  const { t, i18n } = useTranslation()
  const { data, error, isPending } = useQuery({ queryKey: ACCOUNTS_QUERY_KEY, queryFn: listAccounts })
  const [actionFailure, setActionFailure] = useState<unknown>(null)
  const totalAccountCount = data?.length ?? 0
  const hasRows = totalAccountCount > 0
  const accountFilter = useClientFilter(data ?? NO_ACCOUNTS, (account) => [
    account.account_name,
    t(`accounts.roles.${account.account_role}`),
    t(account.second_factor_enrolled ? 'accounts.enrolled' : 'accounts.notEnrolled'),
    t(account.locked ? 'accounts.lockedYes' : 'accounts.lockedNo'),
    formatDateTime(account.created_at, i18n.language),
  ])
  return (
    <section className="space-y-4">
      <PageHeader
        title={t('accounts.title')}
        actions={
          <>
            {hasRows && <DensityToggle />}
            <CreateAccountDialog />
          </>
        }
      />
      {error && <ErrorNotice error={error} />}
      {actionFailure !== null && <ErrorNotice error={actionFailure} />}
      {isPending && <TableSkeleton />}
      <ClientFilterField
        id="accounts-filter"
        label={t('clientFilter.label')}
        value={accountFilter.filterText}
        onChange={accountFilter.setFilterText}
        visibleCount={accountFilter.visibleRows.length}
        totalCount={totalAccountCount}
      />
      {data && (
        <ClientFilterResults visibleCount={accountFilter.visibleRows.length} totalCount={totalAccountCount}>
          <AccountsTable accounts={accountFilter.visibleRows} onFailed={setActionFailure} onSucceeded={() => setActionFailure(null)} />
        </ClientFilterResults>
      )}
    </section>
  )
}
