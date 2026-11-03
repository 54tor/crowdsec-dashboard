import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { runSync, SYNC_QUERY_KEY } from '@/api/syncApi'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'

interface SyncNowButtonProps {
  disabled: boolean
  onStarted: () => void
}

export function SyncNowButton({ disabled, onStarted }: SyncNowButtonProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const isPostInFlight = useRef(false)
  const run = useMutation({
    mutationFn: runSync,
    onSuccess: () => {
      onStarted()
      void queryClient.invalidateQueries({ queryKey: SYNC_QUERY_KEY })
    },
    onError: () => {
      isPostInFlight.current = false
    },
  })
  useEffect(() => {
    if (disabled) {
      isPostInFlight.current = false
    }
  }, [disabled])
  const startRun = () => {
    if (isPostInFlight.current) {
      return
    }
    isPostInFlight.current = true
    run.mutate()
  }
  return (
    <div className="space-y-2">
      <Button type="button" disabled={disabled || run.isPending} onClick={startRun}>
        {t('sync.syncNow')}
      </Button>
      {run.isError && <ErrorNotice error={run.error} />}
    </div>
  )
}
