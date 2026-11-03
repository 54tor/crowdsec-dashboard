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
import { hasUnavailableAllowlist, isGuardedPeer } from '@/lib/syncCodes'

function useSyncStatus() {
  const [isAwaitingStart, setIsAwaitingStart] = useState(false)
  const query = useQuery({
    queryKey: SYNC_QUERY_KEY,
    queryFn: getSyncStatus,
    refetchInterval: (currentQuery) => (currentQuery.state.data?.running || isAwaitingStart ? SYNC_POLL_INTERVAL_MILLISECONDS : false),
  })
  const isRunning = query.data?.running === true

  useEffect(() => {
    if (isRunning) {
      setIsAwaitingStart(false)
    }
  }, [isRunning])

  useEffect(() => {
    if (!isAwaitingStart) {
      return undefined
    }
    const stopWaiting = setTimeout(() => setIsAwaitingStart(false), SYNC_START_WAIT_MILLISECONDS)
    return () => clearTimeout(stopWaiting)
  }, [isAwaitingStart])

  return { ...query, awaitStart: () => setIsAwaitingStart(true) }
}

function SyncNotices({ status }: { status: SyncStatus }) {
  const { t } = useTranslation()
  const unavailablePeers = status.peers.filter(hasUnavailableAllowlist)
  return (
    <>
      {status.dry_run && <WarningNotice title={t('sync.dryRunTitle')}>{t('sync.dryRun')}</WarningNotice>}
      {!status.enabled && <InfoNotice>{t('sync.disabled')}</InfoNotice>}
      {status.running && <InfoNotice>{t('sync.running')}</InfoNotice>}
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
  const { data, error, isPending, awaitStart } = useSyncStatus()
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
          {canWrite && <SyncNowButton disabled={data.running || !data.enabled} guardedPeerNames={data.peers.filter(isGuardedPeer).map((peer) => peer.name)} onStarted={awaitStart} />}
          <h2 className="text-base font-medium">{t('sync.peersCaption')}</h2>
          {data.peers.length === 0 ? <p>{t('sync.noPeers')}</p> : <SyncPeersTable peers={data.peers} />}
          <h2 className="text-base font-medium">{t('sync.planCaption')}</h2>
          {data.last_plan.length === 0 ? <p>{t('sync.noPlan')}</p> : <SyncPlanTable entries={data.last_plan} />}
        </>
      )}
    </section>
  )
}
