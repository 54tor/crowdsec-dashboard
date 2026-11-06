import { apiFetch } from '@/api/client'
import { withEngine } from '@/api/engineQuery'

export interface ConfigEditFile {
  name: string
  exists: boolean
  read_only: boolean
  writable: boolean
  digest: string
  content: string
}

export type IssueSeverity = 'error' | 'warning'

export interface ConfigIssue {
  line: number
  path: string
  severity: IssueSeverity
  code: string
}

export interface ConfigBackup {
  id: number
  created_at: string
  account_name: string
  size: number
}

export interface SaveResult {
  created: boolean
  digest: string
  rolled_back: boolean
  backup_stored: boolean
}

export interface ConfigEditFailureDetails {
  line?: number
  issues?: ConfigIssue[]
  rolledBack: boolean
  affectedFiles: string[]
}

export const OVERRIDES_FILE_NAME = 'config.yaml.local'

const PROTECTED_FILE_NAMES = ['config.yaml', 'acquis.yaml', 'profiles.yaml']

export const isProtectedFromDeletion = (fileName: string) => PROTECTED_FILE_NAMES.includes(fileName)

function encodeFilePath(fileName: string): string {
  return fileName.split('/').map(encodeURIComponent).join('/')
}

function sendJson<T>(method: 'POST' | 'PUT' | 'DELETE', path: string, body: unknown): Promise<T> {
  return apiFetch<T>(path, { method, body: JSON.stringify(body) })
}

export const getConfigEditFile = (fileName: string, engine?: string) =>
  apiFetch<ConfigEditFile>(withEngine(`/api/config/edit/${encodeFilePath(fileName)}`, engine))

export const validateConfigContent = (fileName: string, content: string, engine?: string) =>
  sendJson<{ issues: ConfigIssue[] }>('POST', withEngine('/api/config/edit/validate', engine), { name: fileName, content })

export const saveConfigContent = (fileName: string, content: string, expectedDigest: string, engine?: string) =>
  sendJson<SaveResult>('PUT', withEngine(`/api/config/edit/${encodeFilePath(fileName)}`, engine), { content, expected_digest: expectedDigest })

export const deleteConfigFile = (fileName: string, expectedDigest: string, confirm: string, engine?: string) =>
  sendJson<unknown>('DELETE', withEngine(`/api/config/edit/${encodeFilePath(fileName)}`, engine), { expected_digest: expectedDigest, confirm })

export const listConfigBackups = async (fileName: string, engine?: string) =>
  (await apiFetch<{ items: ConfigBackup[] }>(withEngine(`/api/config/backups/${encodeFilePath(fileName)}`, engine))).items

export const restoreConfigBackup = (backupId: number, expectedDigest: string, engine?: string) =>
  sendJson<SaveResult>('POST', withEngine(`/api/config/backups/${backupId}/restore`, engine), { expected_digest: expectedDigest })

export function failureDetailsOf(failure: unknown): ConfigEditFailureDetails {
  const details = typeof failure === 'object' && failure !== null && 'details' in failure ? (failure.details as Record<string, unknown> | undefined) : undefined
  return {
    line: typeof details?.line === 'number' ? details.line : undefined,
    issues: Array.isArray(details?.issues) ? (details.issues as ConfigIssue[]) : undefined,
    rolledBack: details?.rolled_back === true,
    affectedFiles: Array.isArray(details?.affected_files) ? (details.affected_files as string[]) : [],
  }
}

export function failureCodeOf(failure: unknown): string {
  return typeof failure === 'object' && failure !== null && 'code' in failure ? String(failure.code) : 'unknown'
}
