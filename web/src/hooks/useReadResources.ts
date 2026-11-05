import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/api/client'
import { withEngine } from '@/api/engineQuery'
import type { Bouncer, ConfigFileContent, ConfigFileList, HealthReport, HubItem, Machine, MetricsResponse } from '@/api/types'

const HEALTH_REFRESH_MILLISECONDS = 30_000

export const HEALTH_QUERY_KEY = ['health']

export function useHealth() {
  return useQuery({ queryKey: HEALTH_QUERY_KEY, queryFn: () => apiFetch<HealthReport>('/api/health'), refetchInterval: HEALTH_REFRESH_MILLISECONDS })
}

export const HUB_QUERY_KEY = ['hub']
export const BOUNCERS_QUERY_KEY = ['bouncers']
export const MACHINES_QUERY_KEY = ['machines']

interface ItemList<Item> {
  items: Item[]
}

export function useHub(engine: string) {
  return useQuery({ queryKey: [...HUB_QUERY_KEY, engine], queryFn: () => apiFetch<HubItem[]>(withEngine('/api/hub', engine)) })
}

export function useBouncers(engine: string) {
  return useQuery({
    queryKey: [...BOUNCERS_QUERY_KEY, engine],
    queryFn: async () => (await apiFetch<ItemList<Bouncer>>(withEngine('/api/bouncers', engine))).items,
  })
}

export function useMachines(engine: string) {
  return useQuery({
    queryKey: [...MACHINES_QUERY_KEY, engine],
    queryFn: async () => (await apiFetch<ItemList<Machine>>(withEngine('/api/machines', engine))).items,
  })
}

export function useMetrics() {
  return useQuery({ queryKey: ['metrics'], queryFn: () => apiFetch<MetricsResponse>('/api/metrics') })
}

export function useConfigFiles(engine: string) {
  return useQuery({ queryKey: ['config-files', engine], queryFn: () => apiFetch<ConfigFileList>(withEngine('/api/config/files', engine)) })
}

function encodeFilePath(fileName: string): string {
  return fileName.split('/').map(encodeURIComponent).join('/')
}

export function useConfigFile(engine: string, fileName: string | null) {
  return useQuery({
    queryKey: ['config-file', engine, fileName],
    queryFn: () => apiFetch<ConfigFileContent>(withEngine(`/api/config/files/${encodeFilePath(fileName ?? '')}`, engine)),
    enabled: fileName !== null,
  })
}
