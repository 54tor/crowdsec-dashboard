import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  ACCOUNTS_QUERY_KEY,
  changeAccountRole,
  deleteAccount,
  resetAccountSecondFactor,
  revokeAccountSessions,
  unlockAccount,
  type AccountRole,
  type ManagedAccount,
} from '@/api/accountsApi'
import { AccountRoleSelect } from '@/components/AccountRoleSelect'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { Button } from '@/components/ui/button'

interface AccountRowActionsProps {
  account: ManagedAccount
  onFailed: (failure: unknown) => void
  onSucceeded: () => void
}

export function AccountRoleCell({ account, onFailed, onSucceeded }: AccountRowActionsProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const roleChange = useMutation({
    mutationFn: (accountRole: AccountRole) => changeAccountRole(account.account_name, accountRole),
    onSuccess: onSucceeded,
    onError: onFailed,
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ACCOUNTS_QUERY_KEY }),
  })
  return (
    <div className="max-w-40">
      <AccountRoleSelect
        id={`account-role-${account.account_name}`}
        label={t('accounts.roleOf', { name: account.account_name })}
        value={account.account_role}
        onChange={(chosenRole) => roleChange.mutate(chosenRole)}
      />
    </div>
  )
}

export function AccountRowActions({ account, onFailed, onSucceeded }: AccountRowActionsProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const accountName = account.account_name
  const action = useMutation({
    mutationFn: (operation: () => Promise<unknown>) => operation(),
    onSuccess: () => {
      onSucceeded()
      void queryClient.invalidateQueries({ queryKey: ACCOUNTS_QUERY_KEY })
    },
    onError: onFailed,
  })
  return (
    <div className="flex flex-wrap gap-2">
      <RowDeleteAction
        buttonLabel={t('accounts.resetSecondFactor')}
        ariaLabel={t('accounts.resetSecondFactorAria', { name: accountName })}
        title={t('accounts.resetSecondFactorTitle', { name: accountName })}
        description={t('accounts.resetSecondFactorDescription', { name: accountName })}
        target={accountName}
        request={() => resetAccountSecondFactor(accountName)}
        invalidates={[ACCOUNTS_QUERY_KEY]}
      />
      <Button type="button" variant="outline" size="sm" aria-label={t('accounts.revokeSessionsAria', { name: accountName })} disabled={action.isPending} onClick={() => action.mutate(() => revokeAccountSessions(accountName))}>
        {t('accounts.revokeSessions')}
      </Button>
      {account.locked && (
        <Button type="button" variant="outline" size="sm" aria-label={t('accounts.unlockAria', { name: accountName })} disabled={action.isPending} onClick={() => action.mutate(() => unlockAccount(accountName))}>
          {t('accounts.unlock')}
        </Button>
      )}
      <RowDeleteAction
        buttonLabel={t('accounts.delete')}
        ariaLabel={t('accounts.deleteAria', { name: accountName })}
        title={t('accounts.deleteTitle', { name: accountName })}
        description={t('accounts.deleteDescription', { name: accountName })}
        target={accountName}
        request={() => deleteAccount(accountName)}
        invalidates={[ACCOUNTS_QUERY_KEY]}
      />
    </div>
  )
}
