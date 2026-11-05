import { createContext } from 'react'

export interface ReloadRequiredState {
  isReloadRequired: (engineName: string) => boolean
  markReloadRequired: (engineName: string) => void
  clearReloadRequired: (engineName: string) => void
}

export const ReloadRequiredContext = createContext<ReloadRequiredState | null>(null)
