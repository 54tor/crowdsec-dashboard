import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { createEngine, ENGINE_NAMES_QUERY_KEY, ENGINES_QUERY_KEY, updateEngine } from '@/api/enginesApi'
import type { EngineView } from '@/api/types'
import { EngineFormFields } from '@/components/EngineFormFields'
import { ErrorNotice } from '@/components/Notice'
import { PendingLockDialog } from '@/components/PendingLockDialog'
import { Button } from '@/components/ui/button'
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePendingReport } from '@/hooks/usePendingReport'
import { buildEngineInput, initialFormValues, isFormSubmittable, requiredSecrets, type EngineFormValues } from '@/lib/engineForm'

interface EngineFormProps {
  engine?: EngineView
  onSaved: (savedEngine: EngineView) => void
  onClose: () => void
  reportPending: (isPending: boolean) => void
}

function EngineForm({ engine, onSaved, onClose, reportPending }: EngineFormProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [values, setValues] = useState(() => initialFormValues(engine))
  const saving = useMutation({
    mutationFn: () => (engine ? updateEngine(engine.name, buildEngineInput(values, engine)) : createEngine(buildEngineInput(values))),
    onSuccess: (savedEngine) => {
      void queryClient.invalidateQueries({ queryKey: ENGINES_QUERY_KEY })
      void queryClient.invalidateQueries({ queryKey: ENGINE_NAMES_QUERY_KEY })
      onSaved(savedEngine)
    },
  })
  usePendingReport(saving.isPending, reportPending)
  const required = requiredSecrets(values, engine)
  const canSubmit = isFormSubmittable(values, engine) && !saving.isPending

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (canSubmit) {
      saving.mutate()
    }
  }

  return (
    <form onSubmit={submit} className="max-h-[80vh] space-y-4 overflow-y-auto">
      <DialogHeader>
        <DialogTitle>{engine ? t('engines.editTitle', { name: engine.name }) : t('engines.addTitle')}</DialogTitle>
        <DialogDescription>{t('engines.description')}</DialogDescription>
      </DialogHeader>
      <EngineFormFields values={values} required={required} isEditing={engine !== undefined} onChange={(change: Partial<EngineFormValues>) => setValues((current) => ({ ...current, ...change }))} />
      {saving.isError && <ErrorNotice error={saving.error} />}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={saving.isPending} onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" disabled={!canSubmit}>
          {saving.isPending ? t('dialog.working') : engine ? t('engines.save') : t('engines.create')}
        </Button>
      </DialogFooter>
    </form>
  )
}

interface EngineFormDialogProps {
  trigger: ReactNode
  engine?: EngineView
  onSaved: (savedEngine: EngineView) => void
}

export function EngineFormDialog({ trigger, engine, onSaved }: EngineFormDialogProps) {
  const [isOpen, setIsOpen] = useState(false)
  return (
    <PendingLockDialog open={isOpen} onOpenChange={setIsOpen} trigger={trigger}>
      {(reportPending) => (
        <EngineForm
          engine={engine}
          reportPending={reportPending}
          onClose={() => setIsOpen(false)}
          onSaved={(savedEngine) => {
            setIsOpen(false)
            onSaved(savedEngine)
          }}
        />
      )}
    </PendingLockDialog>
  )
}
