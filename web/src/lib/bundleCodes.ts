import type { TFunction } from 'i18next'

export const SKIP_REASON_CODES = [
  'already_installed', 'duplicate', 'expired', 'own_address', 'invalid_target', 'invalid_name', 'too_long', 'unsupported_type', 'too_short', 'origin',
  'prefix_too_wide', 'private', 'engine_address', 'excluded', 'allowlisted', 'allowlist_unavailable', 'unsupported_scope', 'too_recent', 'invalid',
  'forbidden_name', 'forbidden_source', 'redacted_content', 'invalid_yaml', 'too_large', 'not_regular_file', 'unchanged',
]

export const SECTION_PROBLEM_CODES = [
  'import_disabled', 'section_unavailable', 'flush_limit', 'flush_config_unreadable', 'local_alerts_unreadable', 'allowlist_unavailable',
  'alert_import_side_effect', 'alert_import_side_effect_unverifiable', 'alert_import_cleanup_failed', 'config_test_failed', 'config_inconsistent',
  'config_changed_concurrently', 'config_recovery_pending', 'apply_failed', 'import_timeout', 'canceled', 'lapi_unavailable', 'lapi_error',
  'not_found', 'invalid_request', 'cscli_timeout', 'cscli_failed', 'engine_addresses_unknown', 'local_bans_incomplete', 'dependency_missing',
  'sidecar_command_refused', 'sidecar_unavailable',
]

export const WARNING_CODES = ['version_mismatch', 'simulated_decision_may_remain']

export const SECTION_STATUS_CODES = ['applied', 'failed', 'not_run', 'section_unavailable']

export function translateBundleCode(t: TFunction, group: 'skipReasons' | 'problems' | 'status', code: string): string {
  return t(`bundle.${group}.${code}`, { defaultValue: t('bundle.unknownCode', { code }) })
}

export function splitWarning(warning: string): { code: string; detail: string } {
  const separatorIndex = warning.indexOf(':')
  return separatorIndex < 0 ? { code: warning, detail: '' } : { code: warning.slice(0, separatorIndex), detail: warning.slice(separatorIndex + 1) }
}
