import { apiFetch } from '@/api/client'
import type { AllowlistListing, AllowlistMutation, NewAllowlistEntryInput, NewAllowlistInput } from '@/api/types'

export const allowlistsQueryKey = (engineName: string) => ['allowlists', engineName]

function allowlistsPath(engineName: string): string {
  return `/api/engines/${encodeURIComponent(engineName)}/allowlists`
}

function allowlistPath(engineName: string, allowlistName: string): string {
  return `${allowlistsPath(engineName)}/${encodeURIComponent(allowlistName)}`
}

export const listAllowlists = (engineName: string) => apiFetch<AllowlistListing>(allowlistsPath(engineName))

export const createAllowlist = (engineName: string, input: NewAllowlistInput) =>
  apiFetch<AllowlistMutation>(allowlistsPath(engineName), { method: 'POST', body: JSON.stringify(input) })

export const deleteAllowlist = (engineName: string, allowlistName: string, confirm: string) =>
  apiFetch<AllowlistMutation>(allowlistPath(engineName, allowlistName), { method: 'DELETE', body: JSON.stringify({ confirm }) })

export const addAllowlistEntry = (engineName: string, allowlistName: string, input: NewAllowlistEntryInput) =>
  apiFetch<AllowlistMutation>(`${allowlistPath(engineName, allowlistName)}/entries`, { method: 'POST', body: JSON.stringify(input) })

export const removeAllowlistEntry = (engineName: string, allowlistName: string, value: string, confirm: string) =>
  apiFetch<AllowlistMutation>(`${allowlistPath(engineName, allowlistName)}/entries`, { method: 'DELETE', body: JSON.stringify({ value, confirm }) })
