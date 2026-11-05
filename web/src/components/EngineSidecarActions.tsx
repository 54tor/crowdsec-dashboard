import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ENGINE_NAMES_QUERY_KEY, ENGINES_QUERY_KEY } from '@/api/enginesApi'
import { removeSidecar, testSidecar } from '@/api/sidecarApi'
import type { EngineView } from '@/api/types'
import { ConfirmDeleteDialog } from '@/components/ConfirmDeleteDialog'
import { EngineSidecarDialog } from '@/components/EngineSidecarDialog'
import { ErrorNotice, InfoNotice } from '@/components/Notice'
import { SidecarKeyActions } from '@/components/SidecarKeyActions'
import { Button } from '@/components/ui/button'
import { useCanWrite } from '@/hooks/useCanWrite'
import { sidecarErrorMessage } from '@/lib/sidecarErrors'

function SidecarTestButton({ engineName }: { engineName: string }) {
  const { t } = useTranslation()
  const connectionTest = useMutation({ mutationFn: () => testSidecar(engineName) })
  return (
    <div className="min-w-0 space-y-1">
      <Button type="button" size="sm" variant="outline" aria-label={t('engines.sidecar.testAria', { name: engineName })} disabled={connectionTest.isPending} onClick={() => connectionTest.mutate()}>
        {connectionTest.isPending ? t('engines.testing') : t('engines.sidecar.test')}
      </Button>
      {connectionTest.isSuccess && <InfoNotice>{t('engines.sidecar.testOk')}</InfoNotice>}
      {connectionTest.isError && <ErrorNotice error={connectionTest.error} message={sidecarErrorMessage(connectionTest.error)} />}
    </div>
  )
}

function SidecarRemoveAction({ engineName }: { engineName: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [isOpen, setIsOpen] = useState(false)

  function finishRemoval() {
    setIsOpen(false)
    void queryClient.invalidateQueries({ queryKey: ENGINES_QUERY_KEY })
    void queryClient.invalidateQueries({ queryKey: ENGINE_NAMES_QUERY_KEY })
  }

  return (
    <ConfirmDeleteDialog
      open={isOpen}
      trigger={
        <Button type="button" size="sm" variant="outline" aria-label={t('engines.sidecar.removeAria', { name: engineName })}>
          {t('engines.sidecar.remove')}
        </Button>
      }
      onOpen={() => setIsOpen(true)}
      onClose={() => setIsOpen(false)}
      title={t('engines.sidecar.removeTitle', { name: engineName })}
      description={t('engines.sidecar.removeDescription', { name: engineName })}
      target={engineName}
      submitLabel={t('engines.sidecar.remove')}
      request={(confirm) => removeSidecar(engineName, confirm)}
      onDeleted={finishRemoval}
    />
  )
}

function EnrolButton({ engine, labelKey, ariaKey }: { engine: EngineView; labelKey: string; ariaKey: string }) {
  const { t } = useTranslation()
  return (
    <EngineSidecarDialog
      engine={engine}
      trigger={
        <Button type="button" size="sm" variant="outline" aria-label={t(ariaKey, { name: engine.name })}>
          {t(labelKey)}
        </Button>
      }
    />
  )
}

export function EngineSidecarActions({ engine }: { engine: EngineView }) {
  const canWrite = useCanWrite()
  if (engine.is_local || !canWrite) {
    return null
  }
  if (engine.sidecar === null) {
    return <EnrolButton engine={engine} labelKey="engines.sidecar.enrol" ariaKey="engines.sidecar.enrolAria" />
  }
  return (
    <>
      <SidecarTestButton engineName={engine.name} />
      <SidecarKeyActions engine={engine} />
      <EnrolButton engine={engine} labelKey="engines.sidecar.repin" ariaKey="engines.sidecar.repinAria" />
      <SidecarRemoveAction engineName={engine.name} />
    </>
  )
}
