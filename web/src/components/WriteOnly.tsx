import type { ReactNode } from 'react'
import { useCanWrite } from '@/hooks/useCanWrite'

export function WriteOnly({ children }: { children: ReactNode }) {
  return useCanWrite() ? <>{children}</> : null
}
