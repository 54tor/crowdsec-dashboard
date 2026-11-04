import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { SyncPeer } from '@/api/syncApi'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { SyncPeerStatusBadge } from '@/components/SyncPeerStatusBadge'
import { UntrustedText } from '@/components/UntrustedText'
import { formatDateTime, formatNumber } from '@/lib/format'
import { splitBlockedReasons, translateSyncCode } from '@/lib/syncCodes'

export function SyncPeersTable({ peers }: { peers: SyncPeer[] }) {
  const { t, i18n } = useTranslation()
  const columns = useMemo<DataTableColumn<SyncPeer>[]>(
    () => [
      { key: 'name', header: t('sync.columns.name'), noWrap: true, cell: (peer) => <UntrustedText value={peer.name} /> },
      { key: 'host', header: t('sync.columns.host'), noWrap: true, cell: (peer) => <UntrustedText value={peer.url_host} /> },
      {
        key: 'lastRun',
        header: t('sync.columns.lastRun'),
        noWrap: true,
        cell: (peer) => (peer.last_run_at === null ? t('sync.neverRun') : formatDateTime(peer.last_run_at, i18n.language)),
      },
      { key: 'status', header: t('sync.columns.status'), noWrap: true, cell: (peer) => <SyncPeerStatusBadge peerStatus={peer.status} /> },
      { key: 'added', header: t('sync.columns.added'), noWrap: true, cell: (peer) => formatNumber(peer.added, i18n.language) },
      { key: 'removed', header: t('sync.columns.removed'), noWrap: true, cell: (peer) => formatNumber(peer.removed, i18n.language) },
      { key: 'skipped', header: t('sync.columns.skipped'), noWrap: true, cell: (peer) => formatNumber(peer.skipped, i18n.language) },
      { key: 'skippedAllowlisted', header: t('sync.columns.skippedAllowlisted'), noWrap: true, cell: (peer) => formatNumber(peer.skipped_allowlisted, i18n.language) },
      {
        key: 'blocked',
        header: t('sync.columns.blocked'),
        cell: (peer) => splitBlockedReasons(peer.blocked_reason).map((reason) => translateSyncCode(t, 'blocked', reason)).join(', ') || '—',
      },
      { key: 'error', header: t('sync.columns.error'), cell: (peer) => (peer.error_code === '' ? '—' : translateSyncCode(t, 'errorCodes', peer.error_code)) },
    ],
    [t, i18n.language],
  )
  return <DataTable caption={t('sync.peersTableCaption')} columns={columns} rows={peers} rowKey={(peer) => peer.name} emptyMessage={t('sync.noPeers')} />
}
