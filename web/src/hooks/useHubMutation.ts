import { useMutation, useQueryClient } from '@tanstack/react-query'
import { HUB_QUERY_KEY } from '@/hooks/useReadResources'
import { useReloadRequired } from '@/hooks/useReloadRequired'

export function useHubMutation<Variables = void>(mutationFn: (variables: Variables) => Promise<unknown>, onDone?: () => void) {
  const queryClient = useQueryClient()
  const { markReloadRequired } = useReloadRequired()
  return useMutation({
    mutationFn,
    onSuccess: () => {
      markReloadRequired()
      void queryClient.invalidateQueries({ queryKey: HUB_QUERY_KEY })
      onDone?.()
    },
  })
}
