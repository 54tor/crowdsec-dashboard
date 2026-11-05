import { useIsMutating } from '@tanstack/react-query'

export const ENGINE_WRITE_MUTATION_KEY = ['engineWrite']

export function useIsEngineWritePending(): boolean {
  return useIsMutating({ mutationKey: ENGINE_WRITE_MUTATION_KEY }) > 0
}
