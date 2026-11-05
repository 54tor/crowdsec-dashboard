import { useQuery } from '@tanstack/react-query'
import { useCallback, useMemo, useState } from 'react'
import { LOCAL_ENGINE_NAME } from '@/api/engineQuery'
import { ENGINE_NAMES_QUERY_KEY, listEngineNames } from '@/api/enginesApi'
import type { EngineName } from '@/api/types'

const NO_ENGINE_NAMES: EngineName[] = []

function sidecarEngineNamesOf(engineNames: EngineName[]): string[] {
  return engineNames
    .filter((engineName) => !engineName.is_local && engineName.enabled && engineName.has_sidecar)
    .map((engineName) => engineName.name)
}

export function useEngineTarget(): [string, (engineName: string) => void] {
  const [selectedEngineName, setSelectedEngineName] = useState(LOCAL_ENGINE_NAME)
  const writableEngineNames = useWritableEngineNames()
  const isSelectionWritable = writableEngineNames?.includes(selectedEngineName) ?? false
  return [isSelectionWritable ? selectedEngineName : LOCAL_ENGINE_NAME, setSelectedEngineName]
}

export function useWritableEngineNames(): string[] | undefined {
  const engineNamesQuery = useQuery({ queryKey: ENGINE_NAMES_QUERY_KEY, queryFn: listEngineNames, retry: false })
  const loadedEngineNames = engineNamesQuery.isError ? NO_ENGINE_NAMES : engineNamesQuery.data
  return useMemo(
    () => (loadedEngineNames === undefined ? undefined : [LOCAL_ENGINE_NAME, ...sidecarEngineNamesOf(loadedEngineNames)]),
    [loadedEngineNames],
  )
}

export function useIsWritableEngine(): (engineName: string) => boolean {
  const writableEngineNames = useWritableEngineNames()
  return useCallback(
    (engineName: string) => engineName === LOCAL_ENGINE_NAME || (writableEngineNames ?? []).includes(engineName),
    [writableEngineNames],
  )
}
