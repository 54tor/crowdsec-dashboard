import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ACCOUNTS_QUERY_KEY, listAccounts } from '@/api/accountsApi'
import { AccountsTable } from '@/components/AccountsTable'
import { CreateAccountDialog } from '@/components/CreateAccountDialog'
import { ErrorNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'

export function Accounts() {
  const { t } = useTranslation()
  const { data, error, isPending } = useQuery({ queryKey: ACCOUNTS_QUERY_KEY, queryFn: listAccounts })
  const [actionFailure, setActionFailure] = useState<unknown>(null)
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">{t('accounts.title')}</h1>
        <CreateAccountDialog />
      </div>
      {error && <ErrorNotice error={error} />}
      {actionFailure !== null && <ErrorNotice error={actionFailure} />}
      {isPending && <TableSkeleton />}
      {data && <AccountsTable accounts={data} onFailed={setActionFailure} onSucceeded={() => setActionFailure(null)} />}
    </section>
  )
}
