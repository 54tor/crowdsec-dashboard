import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { TOKENS_QUERY_KEY } from '@/api/tokensApi'
import { CreateTokenForm } from '@/components/CreateTokenForm'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { Button } from '@/components/ui/button'

export function CreateTokenDialog() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [isOpen, setIsOpen] = useState(false)

  return (
    <PendingLockDialog open={isOpen} onOpenChange={setIsOpen} trigger={<Button type="button">{t('tokens.add')}</Button>}>
      {(reportPending) => (
        <CreateTokenForm
          onCreated={() => void queryClient.invalidateQueries({ queryKey: TOKENS_QUERY_KEY })}
          onClose={() => setIsOpen(false)}
          reportPending={reportPending}
        />
      )}
    </PendingLockDialog>
  )
}
