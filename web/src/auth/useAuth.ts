import { useContext } from 'react'
import { AuthContext, type AuthState } from './AuthContext'

export function useAuth(): AuthState {
  const authState = useContext(AuthContext)
  if (!authState) {
    throw new Error('useAuth must be used inside AuthProvider')
  }
  return authState
}
