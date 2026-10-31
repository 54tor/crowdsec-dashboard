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
}

export type DegradedPart = 'version' | 'bouncers' | 'machines'

export interface HealthReport {
  version: string
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
}
