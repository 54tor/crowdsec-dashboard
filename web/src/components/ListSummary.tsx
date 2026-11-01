import { useTranslation } from 'react-i18next'
import type { Page } from '@/api/types'
import { formatNumber } from '@/lib/format'

export function ListSummary<Row>({ data }: { data: Page<Row> }) {
  const { t, i18n } = useTranslation()
  if (data.total === undefined) {
    return null
  }
  const formattedTotal = formatNumber(data.total, i18n.language)
  return <p className="text-sm text-muted-foreground">{data.total_capped ? t('list.totalCapped', { total: formattedTotal }) : t('list.totalInfo', { total: formattedTotal })}</p>
}
