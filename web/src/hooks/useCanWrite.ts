import { useAuth } from '@/auth/useAuth'

export function useCanWrite(): boolean {
  return useAuth().accountRole !== 'read_only'
}
