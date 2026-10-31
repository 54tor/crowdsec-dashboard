import { useTranslation } from 'react-i18next'
import { Skeleton } from '@/components/ui/skeleton'

const SKELETON_ROW_COUNT = 5

export function TableSkeleton() {
  const { t } = useTranslation()
  return (
    <div aria-busy="true" className="space-y-2">
      <span className="sr-only" role="status">{t('list.loading')}</span>
      {Array.from({ length: SKELETON_ROW_COUNT }, (_unused, rowPosition) => (
        <Skeleton key={rowPosition} className="h-8 w-full" />
      ))}
    </div>
  )
}
