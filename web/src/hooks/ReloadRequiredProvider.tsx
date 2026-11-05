import { useMemo, useState } from 'react'
import { Outlet } from 'react-router'
import { ReloadRequiredContext } from '@/hooks/ReloadRequiredContext'

function withoutEngine(engineNames: ReadonlySet<string>, removedEngineName: string): ReadonlySet<string> {
  const remainingEngineNames = new Set(engineNames)
  remainingEngineNames.delete(removedEngineName)
  return remainingEngineNames
}

export function ReloadRequiredProvider() {
  const [enginesRequiringReload, setEnginesRequiringReload] = useState<ReadonlySet<string>>(new Set())
  const state = useMemo(
    () => ({
      isReloadRequired: (engineName: string) => enginesRequiringReload.has(engineName),
      markReloadRequired: (engineName: string) => setEnginesRequiringReload((engineNames) => new Set(engineNames).add(engineName)),
      clearReloadRequired: (engineName: string) => setEnginesRequiringReload((engineNames) => withoutEngine(engineNames, engineName)),
    }),
    [enginesRequiringReload],
  )
  return (
    <ReloadRequiredContext.Provider value={state}>
      <Outlet />
    </ReloadRequiredContext.Provider>
  )
}
