import { ApiError, apiFetch } from '@/api/client'
import { withEngine } from '@/api/engineQuery'
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

export const banIp = (ban: BanRequest, engine?: string) => sendJson<StatusResponse>('POST', withEngine('/api/decisions', engine), ban)
export const deleteDecision = (decisionId: string, scope: string, value: string, confirm: string, engine?: string) =>
  deleteConfirmed(withEngine(`/api/decisions/${encodeURIComponent(decisionId)}?${new URLSearchParams({ scope, value })}`, engine), confirm)
export const deleteAlert = (alertId: string, uuid: string, confirm: string, engine?: string) =>
  deleteConfirmed(withEngine(`/api/alerts/${encodeURIComponent(alertId)}?${new URLSearchParams({ uuid: uuid.toLowerCase() })}`, engine), confirm)

export const createBouncer = (name: string, engine?: string) => sendJson<CreatedBouncer>('POST', withEngine('/api/bouncers', engine), { name })
export const deleteBouncer = (name: string, confirm: string, engine?: string) =>
  deleteConfirmed(withEngine(`/api/bouncers/${encodeURIComponent(name)}`, engine), confirm)

export const createMachine = (name: string, engine?: string) => sendJson<CreatedMachine>('POST', withEngine('/api/machines', engine), { name })
export const validateMachine = (name: string, engine?: string) =>
  sendJson<StatusResponse>('POST', withEngine(`/api/machines/${encodeURIComponent(name)}/validate`, engine))
export const deleteMachine = (name: string, confirm: string, engine?: string) =>
  deleteConfirmed(withEngine(`/api/machines/${encodeURIComponent(name)}`, engine), confirm)

export const updateHub = (engine?: string) => sendJson<StatusResponse>('POST', withEngine('/api/hub/update', engine))
export const upgradeHub = (engine?: string) => sendJson<StatusResponse>('POST', withEngine('/api/hub/upgrade', engine))
export const HUB_ITEM_KINDS = ['collections', 'appsec-rules', 'appsec-configs'] as const
export type HubItemKind = (typeof HUB_ITEM_KINDS)[number]
export const isHubItemKind = (type: string): type is HubItemKind => (HUB_ITEM_KINDS as readonly string[]).includes(type)
export const installHubItem = (kind: HubItemKind, name: string, engine?: string) =>
  sendJson<StatusResponse>('POST', withEngine(`/api/hub/${kind}`, engine), { name })
export const removeHubItem = async (kind: HubItemKind, name: string, confirm: string, engine?: string) =>
  deleteConfirmed(withEngine(`/api/hub/${kind}/${encodeSegments(name)}`, engine), confirm)

export const reloadCrowdsec = (engine?: string) => sendJson<StatusResponse>('POST', withEngine('/api/crowdsec/reload', engine))
