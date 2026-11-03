import { ApiError, apiFetch } from '@/api/client'
import type { BanRequest, CreatedBouncer, CreatedMachine } from '@/api/types'

interface StatusResponse {
  status: string
}

function sendJson<T>(method: 'POST' | 'DELETE', path: string, body?: unknown): Promise<T> {
  return apiFetch<T>(path, { method, body: body === undefined ? undefined : JSON.stringify(body) })
}

function deleteConfirmed(path: string, confirm: string): Promise<StatusResponse> {
  return sendJson('DELETE', path, { confirm })
}

const FORBIDDEN_PATH_SEGMENTS = new Set(['', '.', '..'])

function encodeSegments(name: string): string {
  const segments = name.split('/')
  if (segments.some((segment) => FORBIDDEN_PATH_SEGMENTS.has(segment))) {
    throw new ApiError('invalid_request', 0)
  }
  return segments.map(encodeURIComponent).join('/')
}

export const banIp = (ban: BanRequest) => sendJson<StatusResponse>('POST', '/api/decisions', ban)
export const deleteDecision = (decisionId: string, scope: string, value: string, confirm: string) =>
  deleteConfirmed(`/api/decisions/${encodeURIComponent(decisionId)}?${new URLSearchParams({ scope, value })}`, confirm)
export const deleteAlert = (alertId: string, uuid: string, confirm: string) =>
  deleteConfirmed(`/api/alerts/${encodeURIComponent(alertId)}?${new URLSearchParams({ uuid: uuid.toLowerCase() })}`, confirm)

export const createBouncer = (name: string) => sendJson<CreatedBouncer>('POST', '/api/bouncers', { name })
export const deleteBouncer = (name: string, confirm: string) => deleteConfirmed(`/api/bouncers/${encodeURIComponent(name)}`, confirm)

export const createMachine = (name: string) => sendJson<CreatedMachine>('POST', '/api/machines', { name })
export const validateMachine = (name: string) => sendJson<StatusResponse>('POST', `/api/machines/${encodeURIComponent(name)}/validate`)
export const deleteMachine = (name: string, confirm: string) => deleteConfirmed(`/api/machines/${encodeURIComponent(name)}`, confirm)

export const updateHub = () => sendJson<StatusResponse>('POST', '/api/hub/update')
export const upgradeHub = () => sendJson<StatusResponse>('POST', '/api/hub/upgrade')
export const HUB_ITEM_KINDS = ['collections', 'appsec-rules', 'appsec-configs'] as const
export type HubItemKind = (typeof HUB_ITEM_KINDS)[number]
export const isHubItemKind = (type: string): type is HubItemKind => (HUB_ITEM_KINDS as readonly string[]).includes(type)
export const installHubItem = (kind: HubItemKind, name: string) => sendJson<StatusResponse>('POST', `/api/hub/${kind}`, { name })
export const removeHubItem = async (kind: HubItemKind, name: string, confirm: string) =>
  deleteConfirmed(`/api/hub/${kind}/${encodeSegments(name)}`, confirm)

export const reloadCrowdsec = () => sendJson<StatusResponse>('POST', '/api/crowdsec/reload')
