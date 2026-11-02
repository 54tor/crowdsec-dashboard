import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { createAccount, type AccountRole } from '@/api/accountsApi'
import { AccountRoleSelect } from '@/components/AccountRoleSelect'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'

interface CreateAccountFormProps {
  onCreated: () => void
  onClose: () => void
  reportPending: (isPending: boolean) => void
}

export function CreateAccountForm({ onCreated, onClose, reportPending }: CreateAccountFormProps) {
  const { t } = useTranslation()
  const [accountName, setAccountName] = useState('')
  const [password, setPassword] = useState('')
  const [accountRole, setAccountRole] = useState<AccountRole>('read_only')
  const creation = useMutation({ mutationFn: createAccount, onSuccess: onCreated })
  usePendingReport(creation.isPending, reportPending)
  const isValid = accountName.trim() !== '' && password !== ''

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (isValid && !creation.isPending) {
      creation.mutate({ accountName: accountName.trim(), password, accountRole })
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t('accounts.addTitle')}</DialogTitle>
        <DialogDescription>{t('accounts.addDescription')}</DialogDescription>
      </DialogHeader>
      <div className="space-y-3">
        <FormField id="create-account-name" label={t('accounts.nameLabel')} value={accountName} onChange={(changeEvent) => setAccountName(changeEvent.target.value)} />
        <FormField
          id="create-account-password"
          label={t('accounts.passwordLabel')}
          hint={t('accounts.passwordHint')}
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(changeEvent) => setPassword(changeEvent.target.value)}
        />
        <AccountRoleSelect id="create-account-role" label={t('accounts.roleLabel')} value={accountRole} onChange={setAccountRole} />
      </div>
      {creation.isError && <ErrorNotice error={creation.error} />}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={creation.isPending} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" disabled={!isValid || creation.isPending}>
          {creation.isPending ? t('dialog.working') : t('accounts.create')}
        </Button>
      </DialogFooter>
    </form>
  )
}
