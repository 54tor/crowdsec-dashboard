import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { banIp } from '@/api/writeApi'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'
import { validateBanDuration, validateBanReason, validateBanTarget } from '@/lib/banValidation'

const DURATION_PRESETS = ['1h', '24h', '7d', '30d']
const DEFAULT_DURATION = '24h'

interface BanFormProps {
  reportPending: (isPending: boolean) => void
  onBanned: (target: string) => void
  onClose: () => void
}

export function BanForm({ onBanned, onClose, reportPending }: BanFormProps) {
  const { t } = useTranslation()
  const [target, setTarget] = useState('')
  const [duration, setDuration] = useState(DEFAULT_DURATION)
  const [reason, setReason] = useState('')
  const ban = useMutation({ mutationFn: banIp, onSuccess: () => onBanned(target) })
  usePendingReport(ban.isPending, reportPending)

  const targetError = target === '' ? null : validateBanTarget(target)
  const durationError = validateBanDuration(duration)
  const reasonError = validateBanReason(reason)
  const isValid = target !== '' && !targetError && !durationError && !reasonError

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (isValid && !ban.isPending) {
      ban.mutate({ ip: target, duration, reason })
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t('ban.title')}</DialogTitle>
        <DialogDescription>{t('ban.description')}</DialogDescription>
      </DialogHeader>
      <FormField
        id="ban-ip"
        label={t('ban.ip')}
        value={target}
        onChange={(changeEvent) => setTarget(changeEvent.target.value)}
        error={targetError && t(`errors.${targetError}`)}
      />
      <div className="space-y-2">
        <FormField
          id="ban-duration"
          label={t('ban.duration')}
          hint={t('ban.durationHint')}
          value={duration}
          onChange={(changeEvent) => setDuration(changeEvent.target.value)}
          error={durationError && t(`errors.${durationError}`)}
        />
        <div role="group" aria-label={t('ban.presets')} className="flex flex-wrap gap-2">
          {DURATION_PRESETS.map((preset) => (
            <Button key={preset} type="button" size="sm" variant="outline" aria-pressed={duration === preset} onClick={() => setDuration(preset)}>
              {preset}
            </Button>
          ))}
        </div>
      </div>
      <FormField
        id="ban-reason"
        label={t('ban.reason')}
        value={reason}
        onChange={(changeEvent) => setReason(changeEvent.target.value)}
        error={reasonError && t(`errors.${reasonError}`)}
      />
      {ban.error && <ErrorNotice error={ban.error} />}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={ban.isPending} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" disabled={!isValid || ban.isPending}>
          {ban.isPending ? t('dialog.working') : t('ban.submit')}
        </Button>
      </DialogFooter>
    </form>
  )
}
