import type { AuditFilters } from '@/api/auditApi'
import { validateFilters, type FilterErrorKey } from '@/lib/filterValidation'

export type AuditFilterErrorKey = 'actionInvalid' | 'accountInvalid' | FilterErrorKey

export type AuditFilterErrors = Partial<Record<keyof AuditFilters, AuditFilterErrorKey>>

const AUDIT_ACTION_PATTERN = /^[a-z_]{1,64}$/
const ACCOUNT_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/

export function validateAuditFilters(filters: AuditFilters): AuditFilterErrors {
  const sharedErrors = validateFilters({ q: filters.q, since: filters.since, scenario: '', ip: '' })
  const errors: AuditFilterErrors = { ...sharedErrors }
  if (filters.action !== '' && !AUDIT_ACTION_PATTERN.test(filters.action)) {
    errors.action = 'actionInvalid'
  }
  if (filters.account !== '' && !ACCOUNT_NAME_PATTERN.test(filters.account)) {
    errors.account = 'accountInvalid'
  }
  return errors
}
