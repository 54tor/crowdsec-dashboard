import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { addAllowlistEntry } from '@/api/allowlistsApi'
import type { AllowlistMutation, NewAllowlistEntryInput } from '@/api/types'
import { FormField } from '@/components/FormField'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'
import { isValidAllowlistExpiration, wideRangeConfirmationValue } from '@/lib/allowlistValue'

const EXPIRATION_PRESETS = ['1h', '24h', '7d', '30d']

interface AllowlistEntryTarget {
  engineName: string
  allowlistName: string
  onWritten: (mutation: AllowlistMutation) => void
}

interface AllowlistEntryFormProps extends AllowlistEntryTarget {
  onClose: () => void
  reportPending: (isPending: boolean) => void
}

function ExpirationField({ expiration, onChange }: { expiration: string; onChange: (expiration: string) => void }) {
  const { t } = useTranslation()
  const isInvalid = expiration !== '' && !isValidAllowlistExpiration(expiration)
  return (
    <div className="space-y-2">
      <FormField
        id="allowlist-entry-expiration"
        label={t('allowlists.expiration')}
        hint={t('allowlists.expirationHint')}
        value={expiration}
        onChange={(changeEvent) => onChange(changeEvent.target.value)}
        error={isInvalid ? t('allowlists.expirationInvalid') : null}
      />
      <div role="group" aria-label={t('allowlists.presets')} className="flex flex-wrap gap-2">
        <Button type="button" size="sm" variant="outline" aria-pressed={expiration === ''} onClick={() => onChange('')}>
          {t('allowlists.noExpiry')}
        </Button>
        {EXPIRATION_PRESETS.map((preset) => (
          <Button key={preset} type="button" size="sm" variant="outline" aria-pressed={expiration === preset} onClick={() => onChange(preset)}>
            {preset}
          </Button>
        ))}
      </div>
    </div>
  )
}

function WideRangeConfirmation({ expectedValue, typedValue, onChange }: { expectedValue: string; typedValue: string; onChange: (typedValue: string) => void }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-2">
      <WarningNotice>{t('allowlists.wideRangeWarning')}</WarningNotice>
      <FormField
        id="allowlist-entry-confirm"
        label={t('allowlists.wideRangeConfirm', { value: expectedValue })}
        value={typedValue}
        onChange={(changeEvent) => onChange(changeEvent.target.value)}
      />
    </div>
  )
}

function entryInput(value: string, expiration: string, description: string, confirmValue: string | null): NewAllowlistEntryInput {
  return {
    value,
    expiration: expiration === '' ? undefined : expiration,
    description: description === '' ? undefined : description,
    confirm: confirmValue ?? undefined,
  }
}

function AllowlistEntryForm({ engineName, allowlistName, onWritten, onClose, reportPending }: AllowlistEntryFormProps) {
  const { t } = useTranslation()
  const [value, setValue] = useState('')
  const [expiration, setExpiration] = useState('')
  const [description, setDescription] = useState('')
  const [typedConfirmation, setTypedConfirmation] = useState('')
  const addition = useMutation({ mutationFn: (input: NewAllowlistEntryInput) => addAllowlistEntry(engineName, allowlistName, input), onSuccess: onWritten })
  usePendingReport(addition.isPending, reportPending)

  const trimmedValue = value.trim()
  const expectedConfirmation = wideRangeConfirmationValue(trimmedValue)
  const isConfirmed = expectedConfirmation === null || typedConfirmation === expectedConfirmation
  const isExpirationValid = expiration === '' || isValidAllowlistExpiration(expiration)
  const isValid = trimmedValue !== '' && isConfirmed && isExpirationValid

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (isValid && !addition.isPending) {
      addition.mutate(entryInput(trimmedValue, expiration, description, expectedConfirmation))
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t('allowlists.entryTitle', { name: allowlistName })}</DialogTitle>
        <DialogDescription>{t('allowlists.entryDescription')}</DialogDescription>
      </DialogHeader>
      <FormField id="allowlist-entry-value" label={t('allowlists.value')} value={value} onChange={(changeEvent) => setValue(changeEvent.target.value)} />
      {expectedConfirmation !== null && (
        <WideRangeConfirmation expectedValue={expectedConfirmation} typedValue={typedConfirmation} onChange={setTypedConfirmation} />
      )}
      <ExpirationField expiration={expiration} onChange={setExpiration} />
      <FormField
        id="allowlist-entry-description"
        label={t('allowlists.entryComment')}
        value={description}
        onChange={(changeEvent) => setDescription(changeEvent.target.value)}
      />
      {addition.isError && <ErrorNotice error={addition.error} />}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={addition.isPending} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" disabled={!isValid || addition.isPending}>
          {addition.isPending ? t('dialog.working') : t('allowlists.entrySubmit')}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function AllowlistEntryDialog({ engineName, allowlistName, onWritten }: AllowlistEntryTarget) {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)

  function finishAddition(mutation: AllowlistMutation) {
    setIsOpen(false)
    onWritten(mutation)
  }

  return (
    <PendingLockDialog
      open={isOpen}
      onOpenChange={setIsOpen}
      trigger={
        <Button type="button" size="sm" aria-label={t('allowlists.addEntryLabel', { name: allowlistName })}>
          {t('allowlists.addEntry')}
        </Button>
      }
    >
      {(reportPending) => (
        <AllowlistEntryForm
          engineName={engineName}
          allowlistName={allowlistName}
          onWritten={finishAddition}
          onClose={() => setIsOpen(false)}
          reportPending={reportPending}
        />
      )}
    </PendingLockDialog>
  )
}
