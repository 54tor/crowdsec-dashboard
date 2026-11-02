import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ACCOUNTS_QUERY_KEY } from '@/api/accountsApi'
import { CreateAccountForm } from '@/components/CreateAccountForm'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { Button } from '@/components/ui/button'

export function CreateAccountDialog() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [isOpen, setIsOpen] = useState(false)

  function finishCreation() {
    setIsOpen(false)
    void queryClient.invalidateQueries({ queryKey: ACCOUNTS_QUERY_KEY })
  }

  return (
    <PendingLockDialog open={isOpen} onOpenChange={setIsOpen} trigger={<Button type="button">{t('accounts.add')}</Button>}>
      {(reportPending) => <CreateAccountForm onCreated={finishCreation} onClose={() => setIsOpen(false)} reportPending={reportPending} />}
    </PendingLockDialog>
  )
}
