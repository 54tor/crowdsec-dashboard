import { apiFetch } from '@/api/client'
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

function encodeSegments(name: string): string {
  return name.split('/').map(encodeURIComponent).join('/')
}

export const banIp = (ban: BanRequest) => sendJson<StatusResponse>('POST', '/api/decisions', ban)
export const deleteDecision = (decisionId: string, confirm: string) => deleteConfirmed(`/api/decisions/${encodeURIComponent(decisionId)}`, confirm)
export const deleteAlert = (alertId: string, confirm: string) => deleteConfirmed(`/api/alerts/${encodeURIComponent(alertId)}`, confirm)

export const createBouncer = (name: string) => sendJson<CreatedBouncer>('POST', '/api/bouncers', { name })
export const deleteBouncer = (name: string, confirm: string) => deleteConfirmed(`/api/bouncers/${encodeURIComponent(name)}`, confirm)

export const createMachine = (name: string) => sendJson<CreatedMachine>('POST', '/api/machines', { name })
export const validateMachine = (name: string) => sendJson<StatusResponse>('POST', `/api/machines/${encodeURIComponent(name)}/validate`)
export const deleteMachine = (name: string, confirm: string) => deleteConfirmed(`/api/machines/${encodeURIComponent(name)}`, confirm)

export const updateHub = () => sendJson<StatusResponse>('POST', '/api/hub/update')
export const upgradeHub = () => sendJson<StatusResponse>('POST', '/api/hub/upgrade')
export const installCollection = (name: string) => sendJson<StatusResponse>('POST', '/api/hub/collections', { name })
export const removeCollection = (name: string, confirm: string) => deleteConfirmed(`/api/hub/collections/${encodeSegments(name)}`, confirm)

export const reloadCrowdsec = () => sendJson<StatusResponse>('POST', '/api/crowdsec/reload')
