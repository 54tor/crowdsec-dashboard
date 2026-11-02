import { apiFetch } from '@/api/client'

export type AccountRole = 'admin' | 'read_only'

export interface ManagedAccount {
  account_name: string
  account_role: AccountRole
  created_at: string
  second_factor_enrolled: boolean
  locked: boolean
}

export interface NewAccountInput {
  accountName: string
  password: string
  accountRole: AccountRole
}

export const ACCOUNTS_QUERY_KEY = ['accounts']

export const ACCOUNT_ROLES: readonly AccountRole[] = ['admin', 'read_only']

const ACCOUNTS_PATH = '/api/accounts'

const accountPath = (accountName: string) => `${ACCOUNTS_PATH}/${encodeURIComponent(accountName)}`

export const listAccounts = () => apiFetch<ManagedAccount[]>(ACCOUNTS_PATH)

export const createAccount = (input: NewAccountInput) =>
  apiFetch<{ account_name: string }>(ACCOUNTS_PATH, {
    method: 'POST',
    body: JSON.stringify({ account_name: input.accountName, password: input.password, account_role: input.accountRole }),
  })

export const changeAccountRole = (accountName: string, accountRole: AccountRole) =>
  apiFetch<void>(`${accountPath(accountName)}/role`, { method: 'POST', body: JSON.stringify({ account_role: accountRole }) })

const postAccountAction = (accountName: string, action: string) => apiFetch<void>(`${accountPath(accountName)}/${action}`, { method: 'POST' })

export const resetAccountSecondFactor = (accountName: string) => postAccountAction(accountName, 'second-factor/reset')

export const revokeAccountSessions = (accountName: string) => postAccountAction(accountName, 'sessions/revoke')

export const unlockAccount = (accountName: string) => postAccountAction(accountName, 'unlock')

export const deleteAccount = (accountName: string) =>
  apiFetch<void>(accountPath(accountName), { method: 'DELETE', body: JSON.stringify({ confirm: accountName }) })
