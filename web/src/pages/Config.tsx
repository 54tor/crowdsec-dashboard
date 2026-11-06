import { useTranslation } from 'react-i18next'
import { ConfigAdvancedEditor } from '@/components/ConfigAdvancedEditor'
import { ConfigDiscardDialog } from '@/components/ConfigDiscardDialog'
import { ConfigFileNav } from '@/components/ConfigFileNav'
import { ConfigNewFileForm } from '@/components/ConfigNewFileForm'
import { ConfigViewer } from '@/components/ConfigViewer'
import { CheckboxField } from '@/components/CheckboxField'
import { EngineTargetSelect } from '@/components/EngineTargetSelect'
import { PageHeader } from '@/components/PageHeader'
import { ErrorNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useAdvancedMode } from '@/hooks/useAdvancedMode'
import { useCanWrite } from '@/hooks/useCanWrite'
import { useEngineTarget } from '@/hooks/useEngineTarget'
import { useGuardedConfigSelection } from '@/hooks/useGuardedConfigSelection'
import { useConfigFiles } from '@/hooks/useReadResources'

export function Config() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const [engineName, setEngineName] = useEngineTarget()
  const [storedAdvancedMode, setStoredAdvancedMode] = useAdvancedMode()
  const { data, error, isPending } = useConfigFiles(engineName)
  const selection = useGuardedConfigSelection(engineName, setEngineName)
  const isAdvancedMode = canWrite && storedAdvancedMode
  return (
    <section className="space-y-4">
      <PageHeader title={t('config.title')} description={t('config.filesNote')} />
      <EngineTargetSelect id="config-engine" value={engineName} onChange={selection.selectEngine} />
      {canWrite && (
        <CheckboxField
          id="config-advanced-mode"
          label={t('configEdit.advancedMode')}
          checked={isAdvancedMode}
          onChange={(isEnabled) => selection.guard(() => setStoredAdvancedMode(isEnabled))}
        />
      )}
      <p className="text-sm text-muted-foreground">{t('config.redactionNote')}</p>
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {data && (
        <div className="grid gap-4 md:grid-cols-[16rem_minmax(0,1fr)]">
          <div className="space-y-4">
            <ConfigFileNav files={data.files} selectedFile={selection.selectedFile} onSelect={selection.selectFile} />
            {isAdvancedMode && <ConfigNewFileForm onCreate={selection.selectFile} />}
          </div>
          {isAdvancedMode ? (
            <ConfigAdvancedEditor
              engineName={engineName}
              fileName={selection.selectedFile}
              onSelectFile={selection.selectFile}
              onDirtyChange={selection.setHasUnsavedEdits}
              onDeleted={selection.clearSelection}
            />
          ) : (
            <ConfigViewer engineName={engineName} fileName={selection.selectedFile} />
          )}
        </div>
      )}
      <ConfigDiscardDialog isOpen={selection.isDiscardPending} onCancel={selection.cancelPendingChange} onDiscard={selection.applyPendingChange} />
    </section>
  )
}
