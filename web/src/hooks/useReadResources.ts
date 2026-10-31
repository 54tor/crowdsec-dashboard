import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/api/client'
import type { ConfigFileContent, ConfigFileList, HealthReport, HubItem, MetricsResponse } from '@/api/types'

const HEALTH_REFRESH_MILLISECONDS = 30_000

export const HEALTH_QUERY_KEY = ['health']

export function useHealth() {
  return useQuery({ queryKey: HEALTH_QUERY_KEY, queryFn: () => apiFetch<HealthReport>('/api/health'), refetchInterval: HEALTH_REFRESH_MILLISECONDS })
}

export const HUB_QUERY_KEY = ['hub']

export function useHub() {
  return useQuery({ queryKey: HUB_QUERY_KEY, queryFn: () => apiFetch<HubItem[]>('/api/hub') })
}

export function useMetrics() {
  return useQuery({ queryKey: ['metrics'], queryFn: () => apiFetch<MetricsResponse>('/api/metrics') })
}

export function useConfigFiles() {
  return useQuery({ queryKey: ['config-files'], queryFn: () => apiFetch<ConfigFileList>('/api/config/files') })
}

function encodeFilePath(fileName: string): string {
  return fileName.split('/').map(encodeURIComponent).join('/')
}

export function useConfigFile(fileName: string | null) {
  return useQuery({
    queryKey: ['config-file', fileName],
    queryFn: () => apiFetch<ConfigFileContent>(`/api/config/files/${encodeFilePath(fileName ?? '')}`),
    enabled: fileName !== null,
  })
}
