import { createContext } from 'react'

export interface ReloadRequiredState {
  isReloadRequired: boolean
  markReloadRequired: () => void
  clearReloadRequired: () => void
}

export const ReloadRequiredContext = createContext<ReloadRequiredState | null>(null)
