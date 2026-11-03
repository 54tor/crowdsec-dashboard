import { useMutation, useQueryClient } from '@tanstack/react-query'
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
  const run = useMutation({
    mutationFn: runSync,
    onSuccess: () => {
      onStarted()
      void queryClient.invalidateQueries({ queryKey: SYNC_QUERY_KEY })
    },
  })
  return (
    <div className="space-y-2">
      <Button type="button" disabled={disabled || run.isPending} onClick={() => run.mutate()}>
        {t('sync.syncNow')}
      </Button>
      {run.isError && <ErrorNotice error={run.error} />}
    </div>
  )
}
