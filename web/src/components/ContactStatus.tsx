import { useTranslation } from 'react-i18next'
import { Badge } from '@/components/ui/badge'
import { isStale } from '@/lib/format'

interface ContactStatusProps {
  lastContact: string | null
  now: number
  revoked?: boolean
}

export function ContactStatus({ lastContact, now, revoked = false }: ContactStatusProps) {
  const { t } = useTranslation()
  if (revoked) {
    return <Badge variant="destructive">{t('health.revoked')}</Badge>
  }
  if (isStale(lastContact, now)) {
    return (
      <Badge variant="outline" className="border-amber-600 text-amber-800 dark:text-amber-300">
        {t('health.stale')}
      </Badge>
    )
  }
  return <Badge variant="secondary">{t('health.ok')}</Badge>
}
