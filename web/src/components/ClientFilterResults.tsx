import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { EmptyState } from '@/components/EmptyState'

interface ClientFilterResultsProps {
  visibleCount: number
  totalCount: number
  children: ReactNode
}

export function ClientFilterResults({ visibleCount, totalCount, children }: ClientFilterResultsProps) {
  const { t } = useTranslation()
  const filterHidesEveryRow = totalCount > 0 && visibleCount === 0
  if (filterHidesEveryRow) {
    return <EmptyState message={t('clientFilter.noMatch')} />
  }
  return <>{children}</>
}
