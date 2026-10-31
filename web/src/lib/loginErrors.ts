import { ApiError } from '@/api/client'

const RESTART_LOGIN_CODES = new Set([
  'pending_login_expired',
  'account_locked',
  'access_denied',
  'second_factor_setup_not_allowed',
])

export function isLoginRestartFailure(failure: unknown): boolean {
  return failure instanceof ApiError && RESTART_LOGIN_CODES.has(failure.code)
}
