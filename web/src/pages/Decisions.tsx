import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { Decision } from '@/api/types'
import type { DataTableColumn } from '@/components/DataTable'
import { BanDialog } from '@/components/BanDialog'
import { WriteOnly } from '@/components/WriteOnly'
import { useCanWrite } from '@/hooks/useCanWrite'
import { CheckboxField } from '@/components/CheckboxField'
import { EngineCell } from '@/components/EngineCell'
import { DensityToggle } from '@/components/DensityToggle'
import { FilterBar } from '@/components/FilterBar'
import { FiltersDisclosure } from '@/components/FiltersDisclosure'
import { PageHeader } from '@/components/PageHeader'
import { InfoNotice } from '@/components/Notice'
import { PagedTableSection } from '@/components/PagedTableSection'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { UntrustedText } from '@/components/UntrustedText'
import { Badge } from '@/components/ui/badge'
import { deleteDecision } from '@/api/writeApi'
import { PAGE_SIZE, usePagedList } from '@/hooks/usePagedList'
import { useListControls } from '@/hooks/useListControls'
import { formatDateTimeToMinute } from '@/lib/format'
import { isLiveLocalRow } from '@/lib/liveRow'

function decisionRowKey(decision: Decision): string {
  const archiveDecisionId = decision.archive_decision_id ?? null
  if (archiveDecisionId !== null) {
    return `archive/${archiveDecisionId}`
  }
  return `live/${decision.engine}/${decision.id}`
}

export function Decisions() {
  const { t, i18n } = useTranslation()
  const controls = useListControls()
  const canWrite = useCanWrite()
  const [includeExpired, setIncludeExpired] = useState(false)
  const query = usePagedList<Decision>('decisions', controls.filters, controls.page, PAGE_SIZE, controls.isValid, includeExpired)
  const includeExpiredFilterCount = includeExpired ? 1 : 0
  const activeFilterCount = controls.activeFilterCount + includeExpiredFilterCount
  const hasRows = (query.data?.items.length ?? 0) > 0

  function changeIncludeExpired(isChecked: boolean) {
    setIncludeExpired(isChecked)
    controls.setPage(1)
  }

  const columns = useMemo<DataTableColumn<Decision>[]>(
    () => [
      {
        key: 'value',
        header: t('decisions.columns.value'),
        mobile: 'primary',
        noWrap: true,
        className: 'font-mono',
        cell: (decision) => <UntrustedText value={decision.value} />,
      },
      {
        key: 'engine',
        header: t('decisions.columns.engine'),
        noWrap: true,
        cell: (decision) => <EngineCell engineName={decision.engine} badgeLabel={decision.live ? undefined : t('decisions.archivedBadge')} />,
      },
      { key: 'scope', header: t('decisions.columns.scope'), noWrap: true, cell: (decision) => <UntrustedText value={decision.scope} /> },
      { key: 'type', header: t('decisions.columns.type'), noWrap: true, cell: (decision) => <UntrustedText value={decision.type} /> },
      { key: 'origin', header: t('decisions.columns.origin'), noWrap: true, cell: (decision) => <UntrustedText value={decision.origin} /> },
      {
        key: 'scenario',
        header: t('decisions.columns.scenario'),
        className: 'font-mono',
        cell: (decision) => (
          <>
            <UntrustedText value={decision.scenario} />
            {decision.simulated && <Badge variant="warning" className="ml-2">{t('decisions.columns.simulated')}</Badge>}
          </>
        ),
      },
      {
        key: 'expires',
        header: t('decisions.columns.expires'),
        mobile: 'primary',
        noWrap: true,
        className: 'font-mono',
        cell: (decision) => (decision.until ? formatDateTimeToMinute(decision.until, i18n.language) : <UntrustedText value={decision.duration} />),
      },
      ...(canWrite ? ([{
        key: 'actions',
        header: t('decisions.actions'),
        mobile: 'actions',
        cell: (decision) =>
          isLiveLocalRow(decision) ? (
            <RowDeleteAction
              buttonLabel={t('decisions.unban')}
              ariaLabel={t('decisions.unbanAria', { target: decision.value })}
              title={t('decisions.unbanTitle', { target: decision.value })}
              description={t('decisions.unbanDescription', { id: decision.id, target: decision.value })}
              target={decision.value}
              confirmValue={String(decision.id)}
              request={(confirm) => deleteDecision(String(decision.id), decision.scope, decision.value, confirm)}
              invalidates={[['decisions'], ['alerts']]}
            />
          ) : null,
      }] satisfies DataTableColumn<Decision>[]) : []),
    ],
    [t, i18n.language, canWrite],
  )

  return (
    <section className="space-y-4">
      <PageHeader
        title={t('decisions.title')}
        actions={
          <>
            <WriteOnly>
              <BanDialog />
            </WriteOnly>
            {hasRows && <DensityToggle />}
          </>
        }
      />
      <InfoNotice>{t('decisions.communityNotice')}</InfoNotice>
      <FiltersDisclosure activeFilterCount={activeFilterCount} hasInvalidFilter={!controls.isValid}>
        <FilterBar values={controls.draftFilters} errors={controls.errors} onChange={controls.changeFilter} />
        <CheckboxField id="decisions-include-expired" label={t('decisions.includeExpired')} checked={includeExpired} onChange={changeIncludeExpired} />
      </FiltersDisclosure>
      <PagedTableSection
        query={query}
        page={controls.page}
        onPageChange={controls.setPage}
        isLiveWindowRead={controls.isLiveWindowRead}
        caption={includeExpired ? t('decisions.captionWithExpired') : t('decisions.caption')}
        columns={columns}
        rowKey={decisionRowKey}
        cardsOnMobile
        emptyMessage={t('decisions.empty')}
      />
    </section>
  )
}
