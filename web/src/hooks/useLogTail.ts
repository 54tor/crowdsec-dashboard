import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { fetchLogLines } from '@/api/logsApi'
import { LOG_LINES_REQUESTED, LOG_POLL_INTERVAL_MILLISECONDS } from '@/lib/logPolling'

export function useLogTail(engineName: string, sourceId: string | undefined) {
  return useQuery({
    queryKey: ['log-tail', engineName, sourceId],
    queryFn: () => fetchLogLines(engineName, sourceId ?? '', LOG_LINES_REQUESTED),
    enabled: sourceId !== undefined,
    refetchInterval: LOG_POLL_INTERVAL_MILLISECONDS,
    placeholderData: keepPreviousData,
    retry: false,
  })
}
