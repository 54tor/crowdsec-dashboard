import { useTranslation } from 'react-i18next'
import { CollectorTable } from '@/components/CollectorTable'
import { BouncersTable, MachinesTable } from '@/components/HealthTables'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useHealth } from '@/hooks/useReadResources'

export function Health() {
  const { t } = useTranslation()
  const { data, dataUpdatedAt, error, isPending } = useHealth()
  return (
    <section className="space-y-4">
      <h1 className="text-xl font-semibold">{t('health.title')}</h1>
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {data && (
        <>
          {data.degraded.length > 0 && (
            <WarningNotice title={t('health.degradedTitle')}>
              <ul className="list-disc pl-4">
                {data.degraded.map((degradedPart) => (
                  <li key={degradedPart}>{t(`health.degraded.${degradedPart}`)}</li>
                ))}
              </ul>
            </WarningNotice>
          )}
          <p className="text-sm">
            {t('health.version')} : <span className="font-mono">{data.version}</span>
          </p>
          <p className="text-sm">
            {t('health.database.label')} : <span>{data.database === 'ok' ? t('health.database.ok') : t('health.database.unavailable')}</span>
            {data.schema_version !== null && (
              <>
                {' · '}
                {t('health.database.schemaVersion')} : <span className="font-mono">{data.schema_version}</span>
              </>
            )}
          </p>
          <h2 className="text-base font-medium">{t('health.collector.caption')}</h2>
          <CollectorTable engines={data.collector} now={dataUpdatedAt} />
          <h2 className="text-base font-medium">{t('health.bouncersCaption')}</h2>
          <BouncersTable bouncers={data.bouncers} now={dataUpdatedAt} />
          <h2 className="text-base font-medium">{t('health.machinesCaption')}</h2>
          <MachinesTable machines={data.machines} now={dataUpdatedAt} />
        </>
      )}
    </section>
  )
}
