import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ENGINES_QUERY_KEY, listEngines } from '@/api/enginesApi'
import type { EngineView } from '@/api/types'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { EngineCollectionStatus } from '@/components/EngineCollectionStatus'
import { EngineFormDialog } from '@/components/EngineFormDialog'
import { EngineRowActions } from '@/components/EngineRowActions'
import { PageHeader } from '@/components/PageHeader'
import { ErrorNotice, InfoNotice, WarningNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { errorMessage } from '@/i18n'

function EngineDestination({ engine }: { engine: EngineView }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1 text-sm">
      <p className="font-mono">{engine.lapi_url}</p>
      <p className="text-muted-foreground">{t('engines.machine', { machineId: engine.machine_id })}</p>
      {engine.proxy && (
        <p className="text-muted-foreground">
          {t('engines.proxy', { kind: engine.proxy.kind, url: engine.proxy.url })}
          {engine.has_proxy_credentials && ` (${t('engines.proxyCredentials')})`}
        </p>
      )}
    </div>
  )
}

function EngineState({ engine }: { engine: EngineView }) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap gap-1">
      {engine.is_local && <Badge variant="neutral">{t('engines.local')}</Badge>}
      <Badge variant={engine.enabled ? 'nominal' : 'outline'}>{engine.enabled ? t('engines.enabled') : t('engines.disabled')}</Badge>
      {engine.sync_enabled && <Badge variant="info">{t('engines.syncEnabled')}</Badge>}
    </div>
  )
}

export function Engines() {
  const { t } = useTranslation()
  const [warningCode, setWarningCode] = useState<string | undefined>(undefined)
  const [isDeleting, setIsDeleting] = useState(false)
  const { data: engineList, dataUpdatedAt, error, isPending } = useQuery({ queryKey: ENGINES_QUERY_KEY, queryFn: listEngines })
  const columns = useMemo<DataTableColumn<EngineView>[]>(
    () => [
      { key: 'name', header: t('engines.columns.name'), mobile: 'primary', cell: (engine) => engine.name },
      { key: 'destination', header: t('engines.columns.destination'), cell: (engine) => <EngineDestination engine={engine} /> },
      { key: 'state', header: t('engines.columns.state'), cell: (engine) => <EngineState engine={engine} /> },
      { key: 'collection', header: t('engines.columns.collection'), cell: (engine) => <EngineCollectionStatus engine={engine} now={dataUpdatedAt} /> },
      { key: 'actions', header: t('engines.actions'), mobile: 'actions', cell: (engine) => <EngineRowActions engine={engine} onWarning={setWarningCode} onDeleting={() => setIsDeleting(true)} /> },
    ],
    [t, dataUpdatedAt],
  )
  return (
    <section className="space-y-4">
      <PageHeader
        title={t('engines.title')}
        actions={
          <EngineFormDialog
            onSaved={(savedEngine) => setWarningCode(savedEngine.warning)}
            trigger={<Button type="button">{t('engines.add')}</Button>}
          />
        }
      />
      {isDeleting && <InfoNotice>{t('engines.deleting')}</InfoNotice>}
      {warningCode && <WarningNotice>{errorMessage({ code: warningCode })}</WarningNotice>}
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {engineList && <DataTable caption={t('engines.caption')} columns={columns} rows={engineList} rowKey={(engine) => engine.name} cardsOnMobile emptyMessage={t('engines.empty')} />}
    </section>
  )
}
