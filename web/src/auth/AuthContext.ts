import { createContext } from 'react'
import type { LoginProgress, LoginSecondFactorMethod } from '@/api/loginApi'

export interface AuthState {
  isAuthenticated: boolean
  accountName: string | null
  login(accountName: string, password: string): Promise<LoginProgress>
  verifySecondFactor(method: LoginSecondFactorMethod, value?: string): Promise<void>
  completeLoginSetup(): Promise<void>
  enroll(enrollmentToken: string, accountName: string, password: string): Promise<{ methods: string[] }>
  completeEnrollment(enrollmentToken: string): Promise<void>
  logout(): Promise<void>
}

export const AuthContext = createContext<AuthState | null>(null)
