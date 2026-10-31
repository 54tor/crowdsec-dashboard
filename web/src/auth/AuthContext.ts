import { createContext } from 'react'

export interface AuthState {
  isAuthenticated: boolean
  accountName: string | null
  login(accountName: string, password: string): Promise<void>
  enroll(enrollmentToken: string, accountName: string, password: string): Promise<void>
  logout(): Promise<void>
}

export const AuthContext = createContext<AuthState | null>(null)
