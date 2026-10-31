import { apiFetch } from '@/api/client'

export type AccessRuleKind = 'ip' | 'country'

export interface AccessRule {
  id: number
  kind: string
  value: string
}

export interface AccessRuleList {
  rules: AccessRule[]
  client_ip: string
  client_country: string | null
}

export const ACCESS_RULES_QUERY_KEY = ['access-rules']

const ACCESS_RULES_PATH = '/api/account/access-rules'

export const fetchAccessRules = () => apiFetch<AccessRuleList>(ACCESS_RULES_PATH)

export const addAccessRule = (kind: AccessRuleKind, value: string) =>
  apiFetch<AccessRule>(ACCESS_RULES_PATH, { method: 'POST', body: JSON.stringify({ kind, value }) })

export const deleteAccessRule = (ruleId: number) => apiFetch<void>(`${ACCESS_RULES_PATH}/${ruleId}`, { method: 'DELETE' })
