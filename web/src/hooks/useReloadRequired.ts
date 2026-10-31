import { useQuery, useQueryClient } from '@tanstack/react-query'

const RELOAD_REQUIRED_KEY = ['reload-required']

export function useReloadRequired() {
  const queryClient = useQueryClient()
  const { data: isReloadRequired } = useQuery({
    queryKey: RELOAD_REQUIRED_KEY,
    queryFn: () => false,
    initialData: false,
    staleTime: Infinity,
    gcTime: Infinity,
  })
  return {
    isReloadRequired,
    markReloadRequired: () => queryClient.setQueryData(RELOAD_REQUIRED_KEY, true),
    clearReloadRequired: () => queryClient.setQueryData(RELOAD_REQUIRED_KEY, false),
  }
}
