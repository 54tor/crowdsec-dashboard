import { apiFetch } from '@/api/client'
import type { EngineInput, EngineName, EngineView } from '@/api/types'

export const ENGINES_QUERY_KEY = ['engines']
export const ENGINE_NAMES_QUERY_KEY = ['engine-names']

interface ItemList<Item> {
  items: Item[]
}

interface DeletedEngine {
  status: string
  warning?: string
}

function enginePath(engineName: string): string {
  return `/api/engines/${encodeURIComponent(engineName)}`
}

export async function listEngines(): Promise<EngineView[]> {
  return (await apiFetch<ItemList<EngineView>>('/api/engines')).items
}

export async function listEngineNames(): Promise<EngineName[]> {
  return (await apiFetch<ItemList<EngineName>>('/api/engines/names')).items
}

export const createEngine = (input: EngineInput) =>
  apiFetch<EngineView>('/api/engines', { method: 'POST', body: JSON.stringify(input) })

export const updateEngine = (engineName: string, change: EngineInput) =>
  apiFetch<EngineView>(enginePath(engineName), { method: 'PATCH', body: JSON.stringify(change) })

export const deleteEngine = (engineName: string, confirm: string) =>
  apiFetch<DeletedEngine>(enginePath(engineName), { method: 'DELETE', body: JSON.stringify({ confirm }) })

export const testEngine = (engineName: string) =>
  apiFetch<{ status: string }>(`${enginePath(engineName)}/test`, { method: 'POST' })
