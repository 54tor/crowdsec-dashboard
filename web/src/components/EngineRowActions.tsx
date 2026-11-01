import { useTranslation } from 'react-i18next'
import { deleteEngine, ENGINE_NAMES_QUERY_KEY, ENGINES_QUERY_KEY } from '@/api/enginesApi'
import type { EngineView } from '@/api/types'
import { EngineFormDialog } from '@/components/EngineFormDialog'
import { EngineTestButton } from '@/components/EngineTestButton'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { Button } from '@/components/ui/button'

interface EngineRowActionsProps {
  engine: EngineView
  onWarning: (warningCode: string | undefined) => void
}

export function EngineRowActions({ engine, onWarning }: EngineRowActionsProps) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap items-start gap-2">
      <EngineTestButton engineName={engine.name} />
      {!engine.is_local && (
        <>
          <EngineFormDialog
            engine={engine}
            onSaved={(savedEngine) => onWarning(savedEngine.warning)}
            trigger={
              <Button type="button" size="sm" variant="outline" aria-label={t('engines.editAria', { name: engine.name })}>
                {t('engines.edit')}
              </Button>
            }
          />
          <RowDeleteAction
            buttonLabel={t('common.delete')}
            ariaLabel={t('engines.deleteAria', { name: engine.name })}
            title={t('engines.deleteTitle', { name: engine.name })}
            description={t('engines.deleteDescription', { name: engine.name })}
            target={engine.name}
            request={async (confirm) => onWarning((await deleteEngine(engine.name, confirm)).warning)}
            invalidates={[ENGINES_QUERY_KEY, ENGINE_NAMES_QUERY_KEY]}
          />
        </>
      )}
    </div>
  )
}
