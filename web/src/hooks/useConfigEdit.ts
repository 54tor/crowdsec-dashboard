import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  deleteConfigFile,
  getConfigEditFile,
  listConfigBackups,
  restoreConfigBackup,
  saveConfigContent,
  validateConfigContent,
} from '@/api/configEditApi'
import { ENGINE_WRITE_MUTATION_KEY } from '@/hooks/useIsEngineWritePending'
import { useReloadRequired } from '@/hooks/useReloadRequired'

const CONFIG_EDIT_FILE_KEY = 'config-edit-file'
const CONFIG_BACKUPS_KEY = 'config-backups'
const CONFIG_FILES_KEY = 'config-files'

export function useConfigEditFile(engineName: string, fileName: string | null) {
  return useQuery({
    queryKey: [CONFIG_EDIT_FILE_KEY, engineName, fileName],
    queryFn: () => getConfigEditFile(fileName ?? '', engineName),
    enabled: fileName !== null,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    gcTime: 0,
  })
}

export function useConfigBackups(engineName: string, fileName: string | null) {
  return useQuery({
    queryKey: [CONFIG_BACKUPS_KEY, engineName, fileName],
    queryFn: () => listConfigBackups(fileName ?? '', engineName),
    enabled: fileName !== null,
    gcTime: 0,
  })
}

export function useValidateConfig() {
  return useMutation({
    mutationFn: (variables: { engineName: string; fileName: string; content: string }) =>
      validateConfigContent(variables.fileName, variables.content, variables.engineName),
  })
}

function useRefreshAfterWrite() {
  const queryClient = useQueryClient()
  const { markReloadRequired } = useReloadRequired()
  return async (engineName: string) => {
    markReloadRequired(engineName)
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: [CONFIG_EDIT_FILE_KEY, engineName] }),
      queryClient.invalidateQueries({ queryKey: [CONFIG_BACKUPS_KEY, engineName] }),
      queryClient.invalidateQueries({ queryKey: [CONFIG_FILES_KEY, engineName] }),
    ])
  }
}

export function useSaveConfig() {
  const refreshAfterWrite = useRefreshAfterWrite()
  return useMutation({
    mutationKey: ENGINE_WRITE_MUTATION_KEY,
    mutationFn: (variables: { engineName: string; fileName: string; content: string; expectedDigest: string }) =>
      saveConfigContent(variables.fileName, variables.content, variables.expectedDigest, variables.engineName),
    onSuccess: (_result, variables) => refreshAfterWrite(variables.engineName),
  })
}

export function useDeleteConfig() {
  const refreshAfterWrite = useRefreshAfterWrite()
  return useMutation({
    mutationKey: ENGINE_WRITE_MUTATION_KEY,
    mutationFn: (variables: { engineName: string; fileName: string; expectedDigest: string; confirm: string }) =>
      deleteConfigFile(variables.fileName, variables.expectedDigest, variables.confirm, variables.engineName),
    onSuccess: (_result, variables) => refreshAfterWrite(variables.engineName),
  })
}

export function useRestoreBackup() {
  const refreshAfterWrite = useRefreshAfterWrite()
  return useMutation({
    mutationKey: ENGINE_WRITE_MUTATION_KEY,
    mutationFn: (variables: { engineName: string; backupId: number; expectedDigest: string }) =>
      restoreConfigBackup(variables.backupId, variables.expectedDigest, variables.engineName),
    onSuccess: (_result, variables) => refreshAfterWrite(variables.engineName),
  })
}
