import type { TFunction } from 'i18next'
import type { SyncPeer } from '@/api/syncApi'

const GUARD_REASONS = ['target_guard', 'source_guard']
const ALLOWLIST_UNAVAILABLE = 'allowlist_unavailable'

export function splitBlockedReasons(blockedReason: string): string[] {
  return blockedReason === '' ? [] : blockedReason.split(',')
}

export function isGuardedPeer(peer: SyncPeer): boolean {
  const reasons = splitBlockedReasons(peer.blocked_reason)
  return reasons.some((reason) => GUARD_REASONS.includes(reason)) && !reasons.includes(ALLOWLIST_UNAVAILABLE)
}

export function hasUnavailableAllowlist(peer: SyncPeer): boolean {
  return splitBlockedReasons(peer.blocked_reason).includes(ALLOWLIST_UNAVAILABLE)
}

export function translateSyncCode(t: TFunction, group: 'errorCodes' | 'blocked' | 'reasons' | 'kinds' | 'status', code: string): string {
  return t(`sync.${group}.${code}`, { defaultValue: t('sync.unknownCode', { code }) })
}
