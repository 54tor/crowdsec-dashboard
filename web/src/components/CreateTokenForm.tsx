import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { createToken, type TokenScope } from '@/api/tokensApi'
import { useAuth } from '@/auth/useAuth'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { SecretReveal } from '@/components/SecretReveal'
import { TokenSelect } from '@/components/TokenSelect'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'

const EXPIRY_CHOICES_IN_DAYS = [30, 90, 180, 365]
const DEFAULT_EXPIRY_IN_DAYS = 90

interface CreateTokenFormProps {
  onCreated: () => void
  onClose: () => void
  reportPending: (isPending: boolean) => void
}

export function CreateTokenForm({ onCreated, onClose, reportPending }: CreateTokenFormProps) {
  const { t } = useTranslation()
  const { accountRole } = useAuth()
  const [name, setName] = useState('')
  const [scope, setScope] = useState<TokenScope>('read')
  const [expiresInDays, setExpiresInDays] = useState(DEFAULT_EXPIRY_IN_DAYS)
  const [revealedToken, setRevealedToken] = useState<string | null>(null)
  const creation = useMutation({
    mutationFn: createToken,
    gcTime: 0,
    onSuccess: (created) => {
      setRevealedToken(created.token)
      onCreated()
    },
  })
  usePendingReport(creation.isPending, reportPending)
  const offeredScopes: TokenScope[] = accountRole === 'admin' ? ['read', 'write'] : ['read']
  const isValid = name.trim() !== ''

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (isValid && !creation.isPending) {
      creation.mutate({ name: name.trim(), scope, expiresInDays })
    }
  }

  function close() {
    setRevealedToken(null)
    creation.reset()
    onClose()
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t('tokens.addTitle')}</DialogTitle>
        <DialogDescription>{t('tokens.addDescription')}</DialogDescription>
      </DialogHeader>
      {revealedToken === null ? (
        <div className="space-y-3">
          <FormField id="create-token-name" label={t('tokens.nameLabel')} value={name} onChange={(changeEvent) => setName(changeEvent.target.value)} />
          <TokenSelect
            id="create-token-scope"
            label={t('tokens.scopeLabel')}
            value={scope}
            onChange={(chosenScope) => setScope(chosenScope as TokenScope)}
            options={offeredScopes.map((offeredScope) => ({ value: offeredScope, label: t(`tokens.scopes.${offeredScope}`) }))}
          />
          <TokenSelect
            id="create-token-expiry"
            label={t('tokens.expiryLabel')}
            value={String(expiresInDays)}
            onChange={(chosenDays) => setExpiresInDays(Number(chosenDays))}
            options={EXPIRY_CHOICES_IN_DAYS.map((days) => ({ value: String(days), label: t(`tokens.expiryOptions.${days}`) }))}
          />
        </div>
      ) : (
        <div className="space-y-3">
          <p role="alert" className="text-sm font-medium text-destructive">
            {t('secret.warning')}
          </p>
          <SecretReveal label={t('tokens.secretLabel')} secret={revealedToken} />
        </div>
      )}
      {creation.isError && <ErrorNotice error={creation.error} />}
      <DialogFooter>
        {revealedToken === null ? (
          <>
            <Button type="button" variant="outline" disabled={creation.isPending} onClick={close}>
              {t('dialog.cancel')}
            </Button>
            <Button type="submit" disabled={!isValid || creation.isPending}>
              {creation.isPending ? t('dialog.working') : t('tokens.create')}
            </Button>
          </>
        ) : (
          <Button type="button" onClick={close}>
            {t('secret.done')}
          </Button>
        )}
      </DialogFooter>
    </form>
  )
}
