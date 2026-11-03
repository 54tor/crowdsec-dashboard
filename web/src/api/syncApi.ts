import { apiFetch } from '@/api/client'

export interface SyncPeer {
  name: string
  url_host: string
  last_run_at: string | null
  status: string
  added: number
  removed: number
  skipped: number
  skipped_allowlisted: number
  blocked_reason: string
  error_code: string
}

export interface SyncPlanEntry {
  engine: string
  kind: string
  target: string
  source: string
  reason: string
}

export interface SyncStatus {
  enabled: boolean
  dry_run: boolean
  interval_seconds: number
  running: boolean
  peers: SyncPeer[]
  last_plan: SyncPlanEntry[]
}

export const SYNC_QUERY_KEY = ['sync-status']
export const SYNC_POLL_INTERVAL_MILLISECONDS = 2000
export const SYNC_START_WAIT_MILLISECONDS = 10_000

export const getSyncStatus = () => apiFetch<SyncStatus>('/api/sync')

export const runSync = () => apiFetch<{ status: string }>('/api/sync/run', { method: 'POST', body: JSON.stringify({}) })
