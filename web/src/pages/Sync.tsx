import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { getSyncStatus, SYNC_POLL_INTERVAL_MILLISECONDS, SYNC_QUERY_KEY, SYNC_START_WAIT_MILLISECONDS, type SyncStatus } from '@/api/syncApi'
import { ErrorNotice, InfoNotice, WarningNotice } from '@/components/Notice'
import { SyncNowButton } from '@/components/SyncNowButton'
import { SyncPeersTable } from '@/components/SyncPeersTable'
import { SyncPlanTable } from '@/components/SyncPlanTable'
import { TableSkeleton } from '@/components/TableSkeleton'
import { UntrustedText } from '@/components/UntrustedText'
import { WriteOnly } from '@/components/WriteOnly'
import { useCanWrite } from '@/hooks/useCanWrite'
import { hasUnavailableAllowlist, isGuardedPeer, translateSyncCode } from '@/lib/syncCodes'

function useSyncStatus() {
  const [startedAt, setStartedAt] = useState<number | null>(null)
  const isAwaitingStart = startedAt !== null
  const query = useQuery({
    queryKey: SYNC_QUERY_KEY,
    queryFn: getSyncStatus,
    refetchInterval: (currentQuery) => (currentQuery.state.data?.running || isAwaitingStart ? SYNC_POLL_INTERVAL_MILLISECONDS : false),
  })
  const { dataUpdatedAt } = query

  useEffect(() => {
    if (startedAt !== null && dataUpdatedAt > startedAt) {
      setStartedAt(null)
    }
  }, [startedAt, dataUpdatedAt])

  useEffect(() => {
    if (!isAwaitingStart) {
      return undefined
    }
    const stopWaiting = setTimeout(() => setStartedAt(null), SYNC_START_WAIT_MILLISECONDS)
    return () => clearTimeout(stopWaiting)
  }, [isAwaitingStart])

  return { ...query, isAwaitingStart, awaitStart: () => setStartedAt(Date.now()) }
}

function SyncNotices({ status }: { status: SyncStatus }) {
  const { t } = useTranslation()
  const unavailablePeers = status.peers.filter(hasUnavailableAllowlist)
  const guardedPeers = status.peers.filter(isGuardedPeer)
  return (
    <>
      {status.dry_run && <WarningNotice title={t('sync.dryRunTitle')}>{t('sync.dryRun')}</WarningNotice>}
      {!status.enabled && <InfoNotice>{t('sync.disabled')}</InfoNotice>}
      {status.running && <InfoNotice>{t('sync.running')}</InfoNotice>}
      {status.error_code !== '' && <WarningNotice title={t('sync.runErrorTitle')}>{translateSyncCode(t, 'errorCodes', status.error_code)}</WarningNotice>}
      {guardedPeers.length > 0 && (
        <WarningNotice title={t('sync.guardedTitle')}>
          <p>{t('sync.guarded')}</p>
          <ul className="list-disc pl-4">
            {guardedPeers.map((peer) => (
              <li key={peer.name}>
                <UntrustedText value={peer.name} />
              </li>
            ))}
          </ul>
        </WarningNotice>
      )}
      {unavailablePeers.length > 0 && (
        <WarningNotice title={t('sync.allowlistUnavailableTitle')}>
          <p>{t('sync.allowlistUnavailable')}</p>
          <ul className="list-disc pl-4">
            {unavailablePeers.map((peer) => (
              <li key={peer.name}>
                <UntrustedText value={peer.name} />
              </li>
            ))}
          </ul>
        </WarningNotice>
      )}
    </>
  )
}

export function Sync() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const { data, error, isPending, isAwaitingStart, awaitStart } = useSyncStatus()
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">{t('sync.title')}</h1>
        <WriteOnly>
          <Link to="/engines" className="text-sm underline">
            {t('sync.manageEngines')}
          </Link>
        </WriteOnly>
      </div>
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {data && (
        <>
          <SyncNotices status={data} />
          {canWrite && <SyncNowButton disabled={data.running || !data.enabled || isAwaitingStart} onStarted={awaitStart} />}
          <h2 className="text-base font-medium">{t('sync.peersCaption')}</h2>
          {data.peers.length === 0 ? <p>{t('sync.noPeers')}</p> : <SyncPeersTable peers={data.peers} />}
          <h2 className="text-base font-medium">{t('sync.planCaption')}</h2>
          {data.last_plan.length === 0 ? <p>{t('sync.noPlan')}</p> : <SyncPlanTable entries={data.last_plan} />}
        </>
      )}
    </section>
  )
}
