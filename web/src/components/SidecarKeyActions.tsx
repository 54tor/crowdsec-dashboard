import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ENGINES_QUERY_KEY } from '@/api/enginesApi'
import { promoteSidecarKey, stageSidecarKey, type SidecarKeyChange } from '@/api/sidecarApi'
import type { EngineView } from '@/api/types'
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog'
import { ErrorNotice, InfoNotice } from '@/components/Notice'
import { SidecarKeyLines } from '@/components/SidecarKeyLines'
import { Button } from '@/components/ui/button'
import { sidecarErrorMessage } from '@/lib/sidecarErrors'

type KeyAction = 'stage' | 'promote'

interface KeyOutcome {
  action: KeyAction
  trustedKeyLine: string
}

interface KeyActionDialogProps {
  engineName: string
  action: KeyAction
  request: () => Promise<SidecarKeyChange>
  onDone: (outcome: KeyOutcome) => void
  onFailed: (failure: unknown) => void
}

function KeyActionDialog({ engineName, action, request, onDone, onFailed }: KeyActionDialogProps) {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)
  return (
    <ConfirmActionDialog
      open={isOpen}
      onOpenChange={setIsOpen}
      trigger={
        <Button type="button" size="sm" variant="outline" aria-label={t(`engines.sidecar.${action}Aria`, { name: engineName })}>
          {t(`engines.sidecar.${action}`)}
        </Button>
      }
      title={t(`engines.sidecar.${action}Title`, { name: engineName })}
      description={t(`engines.sidecar.${action}Description`)}
      submitLabel={t(`engines.sidecar.${action}`)}
      request={async () => {
        const keyChange = await request()
        onDone({ action, trustedKeyLine: keyChange.trusted_key_line })
      }}
      onDone={() => setIsOpen(false)}
      onFailed={(failure) => {
        setIsOpen(false)
        onFailed(failure)
      }}
    />
  )
}

export function SidecarKeyActions({ engine }: { engine: EngineView }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [keyOutcome, setKeyOutcome] = useState<KeyOutcome | undefined>(undefined)
  const [keyFailure, setKeyFailure] = useState<unknown>(undefined)
  const hasStagedKey = (engine.sidecar?.next_key_id ?? '') !== ''

  function recordOutcome(outcome: KeyOutcome) {
    setKeyFailure(undefined)
    setKeyOutcome(outcome)
    void queryClient.invalidateQueries({ queryKey: ENGINES_QUERY_KEY })
  }

  function recordFailure(failure: unknown) {
    setKeyOutcome(undefined)
    setKeyFailure(failure)
    void queryClient.invalidateQueries({ queryKey: ENGINES_QUERY_KEY })
  }

  return (
    <>
      <KeyActionDialog engineName={engine.name} action="stage" request={() => stageSidecarKey(engine.name)} onDone={recordOutcome} onFailed={recordFailure} />
      {hasStagedKey && <KeyActionDialog engineName={engine.name} action="promote" request={() => promoteSidecarKey(engine.name)} onDone={recordOutcome} onFailed={recordFailure} />}
      {keyOutcome && (
        <div className="w-full min-w-0 space-y-2">
          <InfoNotice>{t(`engines.sidecar.${keyOutcome.action}Done`)}</InfoNotice>
          <SidecarKeyLines trustedKeyLine={keyOutcome.trustedKeyLine} />
        </div>
      )}
      {keyFailure !== undefined && (
        <div className="w-full min-w-0">
          <ErrorNotice error={keyFailure} message={sidecarErrorMessage(keyFailure)} />
        </div>
      )}
    </>
  )
}
