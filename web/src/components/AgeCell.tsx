import { useTranslation } from 'react-i18next'
import { formatDateTime, formatRelativeAge } from '@/lib/format'

export function AgeCell({ isoDate, now }: { isoDate: string | null; now: number }) {
  const { t, i18n } = useTranslation()
  if (isoDate === null) {
    return <>{t('health.never')}</>
  }
  return (
    <time dateTime={isoDate} title={formatDateTime(isoDate, i18n.language)}>
      {formatRelativeAge(isoDate, now, i18n.language)}
    </time>
  )
}
