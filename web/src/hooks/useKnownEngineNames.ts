import { useQuery } from '@tanstack/react-query'
import { ENGINE_NAMES_QUERY_KEY, listEngineNames } from '@/api/enginesApi'

export function useKnownEngineNames(): string[] | undefined {
  const engineNamesQuery = useQuery({ queryKey: ENGINE_NAMES_QUERY_KEY, queryFn: listEngineNames, retry: false })
  if (engineNamesQuery.isError) {
    return []
  }
  return engineNamesQuery.data?.map((engineName) => engineName.name)
}
