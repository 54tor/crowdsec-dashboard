import { useTranslation } from 'react-i18next'
import type { Alert } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import { alertStatusOf, type AlertStatus } from '@/lib/alertStatus'

const BADGE_BY_STATUS: Record<AlertStatus, { variant: 'warning' | 'critical' | 'info'; labelKey: string }> = {
  simulated: { variant: 'warning', labelKey: 'alerts.simulated' },
  activeBan: { variant: 'critical', labelKey: 'alerts.status.activeBan' },
  report: { variant: 'info', labelKey: 'alerts.status.report' },
}

export function AlertStatusBadge({ alertRow }: { alertRow: Alert }) {
  const { t } = useTranslation()
  const { variant, labelKey } = BADGE_BY_STATUS[alertStatusOf(alertRow)]
  return <Badge variant={variant}>{t(labelKey)}</Badge>
}
