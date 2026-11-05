import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useAuditList, type AuditEvent } from '@/api/auditApi'
import { AuditFilterBar } from '@/components/AuditFilterBar'
import type { DataTableColumn } from '@/components/DataTable'
import { DensityToggle } from '@/components/DensityToggle'
import { FiltersDisclosure } from '@/components/FiltersDisclosure'
import { PagedTableSection } from '@/components/PagedTableSection'
import { PageHeader } from '@/components/PageHeader'
import { UntrustedText } from '@/components/UntrustedText'
import { useAuditControls } from '@/hooks/useAuditControls'
import { formatDateTimeToMinute } from '@/lib/format'

function auditEventKey(auditEvent: AuditEvent): number {
  return auditEvent.id
}

function OptionalUntrustedText({ value, placeholder, maxWidthClassName }: { value: string | null; placeholder: string; maxWidthClassName: string }) {
  if (value === null) {
    return <span className="text-muted-foreground">{placeholder}</span>
  }
  return <UntrustedText value={value} maxWidthClassName={maxWidthClassName} />
}

export function Audit() {
  const { t, i18n } = useTranslation()
  const controls = useAuditControls()
  const tableQuery = useAuditList(controls.filters, controls.page, controls.isValid)

  const columns = useMemo<DataTableColumn<AuditEvent>[]>(
    () => [
      {
        key: 'createdAt',
        header: t('audit.columns.createdAt'),
        mobile: 'primary',
        noWrap: true,
        className: 'font-mono',
        cell: (auditEvent) => formatDateTimeToMinute(auditEvent.created_at, i18n.language),
      },
      {
        key: 'account',
        header: t('audit.columns.account'),
        noWrap: true,
        cell: (auditEvent) => <OptionalUntrustedText value={auditEvent.account} placeholder={t('audit.noAccount')} maxWidthClassName="max-w-[24ch]" />,
      },
      {
        key: 'action',
        header: t('audit.columns.action'),
        mobile: 'primary',
        noWrap: true,
        className: 'font-mono',
        cell: (auditEvent) => <UntrustedText value={auditEvent.action} maxWidthClassName="max-w-[32ch]" />,
      },
      {
        key: 'target',
        header: t('audit.columns.target'),
        cell: (auditEvent) => <OptionalUntrustedText value={auditEvent.target} placeholder={t('audit.noTarget')} maxWidthClassName="max-w-[40ch]" />,
      },
      {
        key: 'clientIp',
        header: t('audit.columns.clientIp'),
        noWrap: true,
        className: 'font-mono',
        cell: (auditEvent) => <OptionalUntrustedText value={auditEvent.client_ip} placeholder={t('audit.noClientIp')} maxWidthClassName="max-w-[40ch]" />,
      },
    ],
    [t, i18n.language],
  )

  const hasRows = (tableQuery.data?.items.length ?? 0) > 0

  return (
    <section className="space-y-4">
      <PageHeader title={t('audit.title')} actions={hasRows && <DensityToggle />} />
      <FiltersDisclosure activeFilterCount={controls.activeFilterCount} hasInvalidFilter={!controls.isValid}>
        <AuditFilterBar values={controls.draftFilters} errors={controls.errors} onChange={controls.changeFilter} />
      </FiltersDisclosure>
      <PagedTableSection
        query={tableQuery}
        page={controls.page}
        onPageChange={controls.setPage}
        isLiveWindowRead={false}
        caption={t('audit.caption')}
        columns={columns}
        rowKey={auditEventKey}
        cardsOnMobile
        emptyMessage={t('audit.empty')}
      />
    </section>
  )
}
