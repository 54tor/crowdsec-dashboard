import type { Alert, Decision, HealthReport, Page } from '@/api/types'

export const MALICIOUS_SCENARIO = '<img src=x onerror=alert(1)>'

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
