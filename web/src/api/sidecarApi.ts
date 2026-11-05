import { apiFetch } from '@/api/client'
import type { EngineSidecarView } from '@/api/types'

export interface SidecarObservation {
  spki_sha256: string
}

export interface SidecarEnrolmentInput {
  url: string
  spki_sha256: string
  confirm: string
}

export interface SidecarEnrolment {
  sidecar: EngineSidecarView
  trusted_key_line: string
  issuer: string
  audience: string
}

export interface SidecarKeyChange {
  sidecar: EngineSidecarView
  trusted_key_line: string
}

interface StatusResponse {
  status: string
}

function sidecarPath(engineName: string): string {
  return `/api/engines/${encodeURIComponent(engineName)}/sidecar`
}

export const observeSidecar = (engineName: string, url: string) =>
  apiFetch<SidecarObservation>(`${sidecarPath(engineName)}/observe`, { method: 'POST', body: JSON.stringify({ url }) })

export const configureSidecar = (engineName: string, enrolment: SidecarEnrolmentInput) =>
  apiFetch<SidecarEnrolment>(sidecarPath(engineName), { method: 'PUT', body: JSON.stringify(enrolment) })

export const testSidecar = (engineName: string) => apiFetch<StatusResponse>(`${sidecarPath(engineName)}/test`, { method: 'POST' })

export const stageSidecarKey = (engineName: string) => apiFetch<SidecarKeyChange>(`${sidecarPath(engineName)}/keys/next`, { method: 'POST' })

export const promoteSidecarKey = (engineName: string) =>
  apiFetch<SidecarKeyChange>(`${sidecarPath(engineName)}/keys/promote`, { method: 'POST' })

export const removeSidecar = (engineName: string, confirm: string) =>
  apiFetch<StatusResponse>(sidecarPath(engineName), { method: 'DELETE', body: JSON.stringify({ confirm }) })
