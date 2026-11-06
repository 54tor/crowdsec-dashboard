import { apiFetch } from '@/api/client'
import { withEngine } from '@/api/engineQuery'

export interface LogSource {
  id: string
  label: string
}

export interface UnreadableLogSource {
  kind: string
  detail: string
}

export interface LogSources {
  engine: string
  sources: LogSource[]
  unreadable: UnreadableLogSource[]
  truncated: boolean
}

export interface LogLines {
  engine: string
  source_id: string
  lines: string[]
  file_size: number
  truncated: boolean
}

export function fetchLogSources(engine: string): Promise<LogSources> {
  return apiFetch<LogSources>(withEngine('/api/logs/sources', engine))
}

export function fetchLogLines(engine: string, sourceId: string, lineCount: number): Promise<LogLines> {
  return apiFetch<LogLines>(withEngine(`/api/logs/sources/${encodeURIComponent(sourceId)}?lines=${lineCount}`, engine))
}
