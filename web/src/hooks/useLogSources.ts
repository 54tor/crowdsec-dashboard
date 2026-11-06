import { useQuery } from '@tanstack/react-query'
import { fetchLogSources } from '@/api/logsApi'

export function useLogSources(engineName: string) {
  return useQuery({ queryKey: ['log-sources', engineName], queryFn: () => fetchLogSources(engineName), retry: false })
}
