import { useTranslation } from 'react-i18next'
import type { EngineView } from '@/api/types'
import { AgeCell } from '@/components/AgeCell'
import { errorMessage } from '@/i18n'

export function EngineCollectionStatus({ engine, now }: { engine: EngineView; now: number }) {
  const { t } = useTranslation()
  const { collection } = engine
  return (
    <div className="space-y-1 text-sm">
      <p>
        {t('engines.status.lastCollected')} {collection.last_collected_at ? <AgeCell isoDate={collection.last_collected_at} now={now} /> : t('engines.status.never')}
      </p>
      {collection.last_error_code && <p className="text-destructive">{errorMessage({ code: collection.last_error_code })}</p>}
      {collection.consecutive_failures > 0 && <p className="text-muted-foreground">{t('engines.status.failures', { count: collection.consecutive_failures })}</p>}
      {collection.gaps > 0 && <p className="text-warning">{t('engines.status.incomplete')}</p>}
    </div>
  )
}
