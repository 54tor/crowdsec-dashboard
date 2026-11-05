import { apiFetch, apiFetchResponse } from '@/api/client'
import { withEngine } from '@/api/engineQuery'

export const BUNDLE_SECTIONS = ['hub', 'decisions', 'alerts', 'config'] as const
export type BundleSection = (typeof BUNDLE_SECTIONS)[number]

export const MAX_BUNDLE_BYTES = 8 * 1024 * 1024
export const SECRETS_CONFIRMATION = 'SECRETS'
export const IMPORT_CONFIRMATION = 'IMPORT'

export interface ExportOptions {
  sections: BundleSection[]
  includeSecrets: boolean
  confirmSecrets: string
}

export interface ExportedBundle {
  blob: Blob
  fileName: string
  skippedAlerts: number
}

export interface HubAction {
  name: string
  version: string
}

export interface DecisionAction {
  scope: string
  value: string
  scenario: string
  until: string
}

export interface AlertAction {
  scenario: string
  start_at: string
  stop_at: string
  scope: string
  value: string
}

export interface FileAction {
  name: string
  change: 'created' | 'updated' | 'unchanged'
  diff: string
  diff_truncated: boolean
}

export interface SkippedItem {
  section: string
  target: string
  reason: string
}

export interface ImportPlan {
  sections: BundleSection[]
  hub: HubAction[]
  decisions: DecisionAction[]
  alerts: AlertAction[]
  config: FileAction[]
  skipped: SkippedItem[]
  skipped_counts: Record<string, Record<string, number>>
  warnings: string[]
  unavailable: BundleSection[]
  unavailable_codes: Record<string, string>
  digest: string
}

export interface SectionReport {
  section: BundleSection
  status: string
  applied: number
  skipped: number
  failed: number
  skipped_reasons: Record<string, number> | null
  error_code?: string
  warnings?: string[]
  affected_files?: string[]
}

export interface ApplyResponse {
  digest: string
  report: { sections: SectionReport[] }
}

export type ParsedBundle = Record<string, unknown>

const FILE_NAME_PATTERN = /^crowdsec-bundle-[0-9A-Za-z-]+\.json$/

function neutralFileName(contentDisposition: string | null): string {
  const headerName = contentDisposition?.match(/filename="([^"]+)"/)?.[1] ?? ''
  if (FILE_NAME_PATTERN.test(headerName)) {
    return headerName
  }
  return `crowdsec-bundle-${new Date().toISOString().slice(0, 10)}.json`
}

export async function exportBundle(options: ExportOptions, engine?: string): Promise<ExportedBundle> {
  const response = await apiFetchResponse(withEngine('/api/export', engine), {
    method: 'POST',
    body: JSON.stringify({
      sections: options.sections,
      include_secrets: options.includeSecrets,
      confirm_secrets: options.includeSecrets ? options.confirmSecrets : '',
      strip_events: false,
    }),
  })
  return {
    blob: await response.blob(),
    fileName: neutralFileName(response.headers.get('Content-Disposition')),
    skippedAlerts: Number(response.headers.get('X-Bundle-Skipped-Alerts') ?? '0') || 0,
  }
}

export const previewImport = (bundle: ParsedBundle, sections: BundleSection[], engine?: string) =>
  apiFetch<ImportPlan>(withEngine('/api/import', engine), { method: 'POST', body: JSON.stringify({ mode: 'preview', bundle, sections }) })

export const applyImport = (bundle: ParsedBundle, sections: BundleSection[], digest: string, engine?: string) =>
  apiFetch<ApplyResponse>(withEngine('/api/import', engine), {
    method: 'POST',
    body: JSON.stringify({ mode: 'apply', bundle, sections, confirm: IMPORT_CONFIRMATION, digest }),
  })
