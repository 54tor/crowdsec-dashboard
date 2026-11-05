import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ENGINE_WRITE_MUTATION_KEY } from '@/hooks/useEngineWritePending'
import { HUB_QUERY_KEY } from '@/hooks/useReadResources'
import { isTimeoutError } from '@/lib/apiErrors'
import { useReloadRequired } from '@/hooks/useReloadRequired'

export interface EngineBoundVariables {
  engineName: string
}

export function useHubMutation<Variables extends EngineBoundVariables>(mutationFn: (variables: Variables) => Promise<unknown>, onDone?: () => void) {
  const queryClient = useQueryClient()
  const { markReloadRequired } = useReloadRequired()
  return useMutation({
    mutationKey: ENGINE_WRITE_MUTATION_KEY,
    mutationFn,
    onSuccess: (_result, variables) => {
      markReloadRequired(variables.engineName)
      void queryClient.invalidateQueries({ queryKey: [...HUB_QUERY_KEY, variables.engineName] })
      onDone?.()
    },
    onError: (failure, variables) => {
      if (isTimeoutError(failure)) {
        markReloadRequired(variables.engineName)
      }
    },
  })
}
