export interface Decision {
  id: number
  alert_id: number
  origin: string
  type: string
  scope: string
  value: string
  duration: string
  until?: string
  scenario: string
  simulated: boolean
  engine: string
  live: boolean
}

export interface AlertSource {
  scope: string
  value: string
  ip?: string
  range?: string
  cn?: string
  as_name?: string
  as_number?: string
}

export interface Alert {
  id: number
  uuid?: string
  engine: string
  archive_id: number | null
  live: boolean
  created_at: string
  machine_id: string
  scenario: string
  message: string
  events_count: number
  start_at: string
  stop_at: string
  simulated: boolean
  source: AlertSource
  decisions: Decision[]
}

export interface Page<Item> {
  items: Item[]
  page: number
  per_page: number
  window_size: number
  may_be_truncated: boolean
  total?: number
  total_capped?: boolean
  live_status?: 'ok' | 'unavailable'
}

export interface AlertEvent {
  timestamp: string
  meta: Record<string, string>
}

export interface AlertDetail extends Alert {
  events_truncated: boolean
  events: AlertEvent[]
}

export interface Bouncer {
  name: string
  type: string
  version: string
  ip_address: string
  last_pull: string | null
  revoked: boolean
  auth_type: string
}

export interface Machine {
  machine_id: string
  ip_address: string
  last_heartbeat: string | null
  version: string
  is_validated: boolean
  auth_type: string
  self: boolean
}

export type DegradedPart = 'version' | 'bouncers' | 'machines'

export interface EngineHealth {
  engine_name: string
  last_success_at: string | null
  lag_seconds: number | null
  errors_total: number
  stale: boolean
}

export interface HealthReport {
  version: string
  database: 'ok' | 'unavailable'
  schema_version: number | null
  collector: EngineHealth[]
  bouncers: Bouncer[]
  machines: Machine[]
  degraded: DegradedPart[]
}

export interface AcquisitionMetric {
  source: string
  lines_read: number
  parsed: number
  unparsed: number
}

export interface ParserMetric {
  name: string
  hits: number
  parsed: number
  unparsed: number
}

export interface MetricsAvailable {
  available: true
  acquisition: AcquisitionMetric[]
  parsers: ParserMetric[]
}

export interface MetricsUnavailable {
  available: false
  reason: string
}

export type MetricsResponse = MetricsAvailable | MetricsUnavailable

export interface ConfigFileList {
  files: string[]
}

export interface ConfigFileContent {
  name: string
  content: string
}

export interface ListFilters {
  scenario: string
  ip: string
  since: string
  engine: string
}

export interface HubItem {
  type: string
  name: string
  status: string
  local_version: string
  description: string
}

export interface BanRequest {
  ip: string
  duration: string
  reason: string
}

export interface CreatedBouncer {
  name: string
  key: string
}

export interface CreatedMachine {
  name: string
  password: string
}

export interface EngineProxyView {
  kind: 'socks5' | 'http'
  url: string
}

export interface EngineCollection {
  cursor: number
  last_collected_at: string | null
  last_error_code: string | null
  consecutive_failures: number
  next_attempt_at: string | null
  inserted: number
  duplicates: number
  skipped: number
  gaps: number
  resets: number
}

export interface EngineView {
  name: string
  is_local: boolean
  lapi_url: string
  machine_id: string
  proxy: EngineProxyView | null
  has_proxy_credentials: boolean
  allow_insecure_http: boolean
  public_addresses: string[]
  enabled: boolean
  sync_enabled: boolean
  collection: EngineCollection
  warning?: string
}

export interface EngineName {
  name: string
  is_local: boolean
  enabled: boolean
}

export interface EngineProxyInput {
  kind: 'socks5' | 'http'
  url: string
  username?: string
  password?: string
  clear_credentials?: boolean
}

export interface EngineInput {
  name?: string
  lapi_url?: string
  machine_id?: string
  machine_password?: string
  proxy?: EngineProxyInput | null
  allow_insecure_http?: boolean
  public_addresses?: string[]
  enabled?: boolean
  sync_enabled?: boolean
}
