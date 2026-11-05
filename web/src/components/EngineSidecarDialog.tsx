import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ENGINE_NAMES_QUERY_KEY, ENGINES_QUERY_KEY } from '@/api/enginesApi'
import { configureSidecar, observeSidecar, type SidecarEnrolment } from '@/api/sidecarApi'
import type { EngineView } from '@/api/types'
import { CheckboxField } from '@/components/CheckboxField'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { SidecarKeyLines } from '@/components/SidecarKeyLines'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'
import { errorMessage } from '@/i18n'
import { sidecarErrorMessage } from '@/lib/sidecarErrors'

const FINGERPRINT_BLOCK_PATTERN = /.{1,4}/g

function groupFingerprint(fingerprint: string): string {
  return (fingerprint.match(FINGERPRINT_BLOCK_PATTERN) ?? []).join(' ')
}

interface EnrolmentFormProps {
  engine: EngineView
  onEnrolled: () => void
  onClose: () => void
  reportPending: (isPending: boolean) => void
}

function EnrolmentResult({ enrolment, isRepin, onClose }: { enrolment: SidecarEnrolment; isRepin: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const resultKeyPrefix = isRepin ? 'engines.sidecar.repinned' : 'engines.sidecar.enrolled'
  return (
    <div className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t(`${resultKeyPrefix}Title`)}</DialogTitle>
        <DialogDescription>{t(`${resultKeyPrefix}Description`)}</DialogDescription>
      </DialogHeader>
      <SidecarKeyLines trustedKeyLine={enrolment.trusted_key_line} issuer={enrolment.issuer} audience={enrolment.audience} />
      <DialogFooter>
        <Button type="button" onClick={onClose}>
          {t('secret.done')}
        </Button>
      </DialogFooter>
    </div>
  )
}

function FingerprintCheck({ fingerprint, isConfirmed, onConfirmedChange }: { fingerprint: string; isConfirmed: boolean; onConfirmedChange: (isChecked: boolean) => void }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-2">
      <p className="text-sm">{t('engines.sidecar.compareFingerprint')}</p>
      <code data-testid="sidecar-fingerprint" className="block rounded-md border bg-secondary p-2 font-mono text-sm break-words">
        {groupFingerprint(fingerprint)}
      </code>
      <CheckboxField id="sidecar-fingerprint-matches" label={t('engines.sidecar.fingerprintMatches')} checked={isConfirmed} onChange={onConfirmedChange} />
    </div>
  )
}

function EnrolmentForm({ engine, onEnrolled, onClose, reportPending }: EnrolmentFormProps) {
  const { t } = useTranslation()
  const [sidecarUrl, setSidecarUrl] = useState(engine.sidecar?.url ?? '')
  const [fingerprint, setFingerprint] = useState<string | undefined>(undefined)
  const [isConfirmed, setIsConfirmed] = useState(false)
  const observation = useMutation({
    mutationFn: () => observeSidecar(engine.name, sidecarUrl),
    onError: () => {
      setFingerprint(undefined)
      setIsConfirmed(false)
    },
    onSuccess: (observed) => {
      setFingerprint(observed.spki_sha256)
      setIsConfirmed(false)
    },
  })
  const enrolment = useMutation({
    mutationFn: (pinnedFingerprint: string) => configureSidecar(engine.name, { url: sidecarUrl, spki_sha256: pinnedFingerprint, confirm: engine.name }),
    onSuccess: onEnrolled,
    onError: () => {
      setFingerprint(undefined)
      setIsConfirmed(false)
    },
  })
  const describeError = engine.sidecar !== null ? sidecarErrorMessage : errorMessage
  const isWorking = observation.isPending || enrolment.isPending
  usePendingReport(isWorking, reportPending)

  if (enrolment.isSuccess) {
    return <EnrolmentResult enrolment={enrolment.data} isRepin={engine.sidecar !== null} onClose={onClose} />
  }

  function changeUrl(nextUrl: string) {
    setSidecarUrl(nextUrl)
    setFingerprint(undefined)
    setIsConfirmed(false)
  }

  function fetchFingerprint(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (sidecarUrl.trim() !== '' && !isWorking) {
      enrolment.reset()
      setFingerprint(undefined)
      setIsConfirmed(false)
      observation.mutate()
    }
  }

  const canPin = fingerprint !== undefined && isConfirmed && !isWorking

  return (
    <form onSubmit={fetchFingerprint} className="max-h-[80vh] min-w-0 space-y-4 overflow-y-auto">
      <DialogHeader>
        <DialogTitle>{t('engines.sidecar.enrolTitle', { name: engine.name })}</DialogTitle>
        <DialogDescription>{t('engines.sidecar.enrolDescription')}</DialogDescription>
      </DialogHeader>
      <FormField id="sidecar-url" type="url" inputMode="url" label={t('engines.sidecar.url')} hint={t('engines.sidecar.urlHint')} value={sidecarUrl} onChange={(changeEvent) => changeUrl(changeEvent.target.value)} />
      <Button type="submit" variant="outline" disabled={sidecarUrl.trim() === '' || isWorking}>
        {observation.isPending ? t('dialog.working') : t('engines.sidecar.fetchFingerprint')}
      </Button>
      {fingerprint !== undefined && <FingerprintCheck fingerprint={fingerprint} isConfirmed={isConfirmed} onConfirmedChange={setIsConfirmed} />}
      {observation.isError && <ErrorNotice error={observation.error} message={describeError(observation.error)} />}
      {enrolment.isError && <ErrorNotice error={enrolment.error} message={describeError(enrolment.error)} />}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={isWorking} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="button" disabled={!canPin} onClick={() => fingerprint !== undefined && enrolment.mutate(fingerprint)}>
          {enrolment.isPending ? t('dialog.working') : t('engines.sidecar.pinAndEnrol')}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function EngineSidecarDialog({ engine, trigger }: { engine: EngineView; trigger: ReactNode }) {
  const queryClient = useQueryClient()
  const [isOpen, setIsOpen] = useState(false)
  const [hasEnrolled, setHasEnrolled] = useState(false)

  function changeOpen(nextIsOpen: boolean) {
    setIsOpen(nextIsOpen)
    if (!nextIsOpen && hasEnrolled) {
      setHasEnrolled(false)
      void queryClient.invalidateQueries({ queryKey: ENGINES_QUERY_KEY })
      void queryClient.invalidateQueries({ queryKey: ENGINE_NAMES_QUERY_KEY })
    }
  }

  return (
    <PendingLockDialog open={isOpen} onOpenChange={changeOpen} trigger={trigger}>
      {(reportPending) => <EnrolmentForm engine={engine} reportPending={reportPending} onEnrolled={() => setHasEnrolled(true)} onClose={() => changeOpen(false)} />}
    </PendingLockDialog>
  )
}
