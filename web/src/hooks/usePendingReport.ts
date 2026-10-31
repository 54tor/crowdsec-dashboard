import { useEffect } from 'react'

export function usePendingReport(isPending: boolean, onPendingChange: (isPending: boolean) => void): void {
  useEffect(() => {
    onPendingChange(isPending)
    return () => onPendingChange(false)
  }, [isPending, onPendingChange])
}
