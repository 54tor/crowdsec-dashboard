import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import type { DegradedPart, HealthReport } from '@/api/types'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useHealth } from '@/hooks/useReadResources'

interface HealthPageSectionProps {
  titleKey: string
  degradedPart: DegradedPart
  toolbar: ReactNode
  children: (report: HealthReport, now: number) => ReactNode
}

export function HealthPageSection({ titleKey, degradedPart, toolbar, children }: HealthPageSectionProps) {
  const { t } = useTranslation()
  const { data, dataUpdatedAt, error, isPending } = useHealth()
  return (
    <section className="space-y-4">
      <PageHeader title={t(titleKey)} actions={toolbar} />
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {data?.degraded.includes(degradedPart) && <WarningNotice>{t(`health.degraded.${degradedPart}`)}</WarningNotice>}
      {data && children(data, dataUpdatedAt)}
    </section>
  )
}
