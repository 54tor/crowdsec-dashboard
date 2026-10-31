import { useContext } from 'react'
import { ReloadRequiredContext, type ReloadRequiredState } from '@/hooks/ReloadRequiredContext'

export function useReloadRequired(): ReloadRequiredState {
  const state = useContext(ReloadRequiredContext)
  if (state === null) {
    throw new Error('useReloadRequired must be used inside ReloadRequiredProvider')
  }
  return state
}
