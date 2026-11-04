import { useTranslation } from 'react-i18next'
import { Badge } from '@/components/ui/badge'
import { translateSyncCode } from '@/lib/syncCodes'

type PeerStatusVariant = 'nominal' | 'warning' | 'critical' | 'outline'

const VARIANT_BY_PEER_STATUS: Record<string, PeerStatusVariant> = {
  ok: 'nominal',
  blocked: 'warning',
  failed: 'critical',
}

export function SyncPeerStatusBadge({ peerStatus }: { peerStatus: string }) {
  const { t } = useTranslation()
  const variant = Object.hasOwn(VARIANT_BY_PEER_STATUS, peerStatus) ? VARIANT_BY_PEER_STATUS[peerStatus] : 'outline'
  return <Badge variant={variant}>{translateSyncCode(t, 'status', peerStatus)}</Badge>
}
