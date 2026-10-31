import { createContext } from 'react'

export interface AuthState {
  isAuthenticated: boolean
  login(password: string): Promise<void>
  logout(): Promise<void>
}

export const AuthContext = createContext<AuthState | null>(null)
