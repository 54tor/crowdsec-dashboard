import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ACCOUNTS_QUERY_KEY, listAccounts } from '@/api/accountsApi'
import { AccountsTable } from '@/components/AccountsTable'
import { CreateAccountDialog } from '@/components/CreateAccountDialog'
import { DensityToggle } from '@/components/DensityToggle'
import { ErrorNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'

export function Accounts() {
  const { t } = useTranslation()
  const { data, error, isPending } = useQuery({ queryKey: ACCOUNTS_QUERY_KEY, queryFn: listAccounts })
  const [actionFailure, setActionFailure] = useState<unknown>(null)
  const hasRows = (data?.length ?? 0) > 0
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
      {data && <AccountsTable accounts={data} onFailed={setActionFailure} onSucceeded={() => setActionFailure(null)} />}
    </section>
  )
}
