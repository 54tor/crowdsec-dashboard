import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { UnreadableLogSource } from '@/api/logsApi'
import { EngineTargetSelect } from '@/components/EngineTargetSelect'
import { LogLines } from '@/components/LogLines'
import { ErrorNotice, InfoNotice } from '@/components/Notice'
import { SelectField } from '@/components/SelectField'
import { useEngineTarget } from '@/hooks/useEngineTarget'
import { useLogSources } from '@/hooks/useLogSources'
import { useLogTail } from '@/hooks/useLogTail'

function UnreadableSources({ unreadableSources }: { unreadableSources: UnreadableLogSource[] }) {
  const { t } = useTranslation()
  if (unreadableSources.length === 0) {
    return null
  }
  return (
    <div className="space-y-1 text-sm text-muted-foreground">
      <p>{t('engineLogs.unreadableTitle')}</p>
      <ul data-testid="unreadable-sources" className="list-disc pl-5">
        {unreadableSources.map((unreadableSource) => (
          <li key={unreadableSource.kind}>{t('engineLogs.unreadableKind', { kind: unreadableSource.kind })}</li>
        ))}
      </ul>
    </div>
  )
}

export function EngineLogs() {
  const { t } = useTranslation()
  const [engineName, setEngineName] = useEngineTarget()
  const [chosenSourceId, setChosenSourceId] = useState<string | undefined>(undefined)
  const sourcesQuery = useLogSources(engineName)
  const sources = sourcesQuery.data?.sources ?? []
  const activeSourceId = sources.find((source) => source.id === chosenSourceId)?.id ?? sources[0]?.id
  const tailQuery = useLogTail(engineName, activeSourceId)
  const isTailOfActiveSource = tailQuery.data?.engine === engineName && tailQuery.data.source_id === activeSourceId
  function selectEngine(nextEngineName: string) {
    setChosenSourceId(undefined)
    setEngineName(nextEngineName)
  }
  return (
    <section className="space-y-3" aria-labelledby="engine-logs-title">
      <div className="space-y-1">
        <h2 id="engine-logs-title" className="font-condensed text-xl font-semibold tracking-tight">
          {t('engineLogs.title')}
        </h2>
        <p className="text-sm text-muted-foreground">{t('engineLogs.description')}</p>
      </div>
      <EngineTargetSelect id="engine-logs-engine" value={engineName} onChange={selectEngine} />
      {sourcesQuery.error && <ErrorNotice error={sourcesQuery.error} />}
      {sourcesQuery.data && sources.length === 0 && <InfoNotice>{t('engineLogs.noSources')}</InfoNotice>}
      {sources.length > 0 && (
        <div className="max-w-xl">
          <SelectField
            id="engine-logs-source"
            label={t('engineLogs.source')}
            value={activeSourceId ?? ''}
            options={sources.map((source) => ({ value: source.id, label: source.label }))}
            onChange={setChosenSourceId}
          />
        </div>
      )}
      {sourcesQuery.data && <UnreadableSources unreadableSources={sourcesQuery.data.unreadable} />}
      {tailQuery.error && <ErrorNotice error={tailQuery.error} />}
      {tailQuery.data && isTailOfActiveSource && !tailQuery.error && <LogLines lines={tailQuery.data.lines} />}
    </section>
  )
}
