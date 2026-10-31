import { useMemo, useState } from 'react'
import { Outlet } from 'react-router'
import { ReloadRequiredContext } from '@/hooks/ReloadRequiredContext'

export function ReloadRequiredProvider() {
  const [isReloadRequired, setIsReloadRequired] = useState(false)
  const state = useMemo(
    () => ({
      isReloadRequired,
      markReloadRequired: () => setIsReloadRequired(true),
      clearReloadRequired: () => setIsReloadRequired(false),
    }),
    [isReloadRequired],
  )
  return (
    <ReloadRequiredContext.Provider value={state}>
      <Outlet />
    </ReloadRequiredContext.Provider>
  )
}
