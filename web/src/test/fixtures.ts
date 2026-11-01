import type { Alert, AlertDetail, Bouncer, Decision, EngineView, HealthReport, HubItem, Machine, Page } from '@/api/types'

export const MALICIOUS_SCENARIO = '<img src=x onerror=alert(1)>'
export const JAVASCRIPT_URL = 'javascript:alert(1)'
export const BIDI_OVERRIDE_SAMPLE = 'evil\u202Egnp.exe'

export function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 1,
    created_at: '2026-10-31T10:15:00Z',
    machine_id: 'machine-one',
    scenario: 'crowdsecurity/ssh-bf',
    message: 'Ip 203.0.113.7 performed crowdsecurity/ssh-bf',
    events_count: 6,
    start_at: '2026-10-31T10:14:00Z',
    stop_at: '2026-10-31T10:15:00Z',
    simulated: false,
    source: { scope: 'Ip', value: '203.0.113.7', ip: '203.0.113.7', cn: 'FR', as_name: 'Example AS' },
    decisions: [],
    engine: 'local',
    archive_id: null,
    live: true,
    ...overrides,
  }
}

export function makeAlertDetail(overrides: Partial<AlertDetail> = {}): AlertDetail {
  return {
    ...makeAlert({ engine: 'edge-1', archive_id: 77, live: false }),
    events_truncated: false,
    events: [],
    ...overrides,
  }
}

export function makeDecision(overrides: Partial<Decision> = {}): Decision {
  return {
    id: 10,
    alert_id: 1,
    origin: 'crowdsec',
    type: 'ban',
    scope: 'Ip',
    value: '203.0.113.7',
    duration: '3h59m',
    until: '2026-10-31T14:15:00Z',
    scenario: 'crowdsecurity/ssh-bf',
    simulated: false,
    engine: 'local',
    live: true,
    ...overrides,
  }
}

export function makePage<Item>(items: Item[], overrides: Partial<Page<Item>> = {}): Page<Item> {
  return {
    items,
    page: 1,
    per_page: 20,
    window_size: items.length,
    may_be_truncated: false,
    ...overrides,
  }
}

export function makeHealth(overrides: Partial<HealthReport> = {}): HealthReport {
  return {
    version: 'v1.7.3',
    bouncers: [],
    machines: [],
    degraded: [],
    ...overrides,
  }
}

export function makeBouncer(overrides: Partial<Bouncer> = {}): Bouncer {
  return {
    name: 'firewall-one',
    type: 'crowdsec-firewall-bouncer',
    version: 'v0.0.31',
    ip_address: '203.0.113.30',
    last_pull: '2026-10-31T10:00:00Z',
    revoked: false,
    auth_type: 'api-key',
    ...overrides,
  }
}

export function makeMachine(overrides: Partial<Machine> = {}): Machine {
  return {
    machine_id: 'machine-one',
    ip_address: '203.0.113.20',
    last_heartbeat: '2026-10-31T10:00:00Z',
    version: 'v1.7.3',
    is_validated: true,
    auth_type: 'password',
    self: false,
    ...overrides,
  }
}

export function makeHubItem(overrides: Partial<HubItem> = {}): HubItem {
  return {
    type: 'collections',
    name: 'crowdsecurity/linux',
    status: 'enabled',
    local_version: '0.2',
    description: 'core linux',
    ...overrides,
  }
}

export function makeEngine(overrides: Partial<EngineView> = {}): EngineView {
  return {
    name: 'remote-one',
    is_local: false,
    lapi_url: 'https://lapi.example.com:8080',
    machine_id: 'dashboard-machine',
    proxy: null,
    has_proxy_credentials: false,
    allow_insecure_http: false,
    public_addresses: [],
    enabled: true,
    sync_enabled: false,
    collection: {
      cursor: 0,
      last_collected_at: null,
      last_error_code: null,
      consecutive_failures: 0,
      next_attempt_at: null,
      inserted: 0,
      duplicates: 0,
      skipped: 0,
      gaps: 0,
      resets: 0,
    },
    ...overrides,
  }
}
