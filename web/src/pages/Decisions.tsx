import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { Decision } from '@/api/types'
import type { DataTableColumn } from '@/components/DataTable'
import { BanDialog } from '@/components/BanDialog'
import { WriteOnly } from '@/components/WriteOnly'
import { useCanWrite } from '@/hooks/useCanWrite'
import { CheckboxField } from '@/components/CheckboxField'
import { EngineCell } from '@/components/EngineCell'
import { FilterBar } from '@/components/FilterBar'
import { InfoNotice } from '@/components/Notice'
import { PagedTableSection } from '@/components/PagedTableSection'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { UntrustedText } from '@/components/UntrustedText'
import { Badge } from '@/components/ui/badge'
import { deleteDecision } from '@/api/writeApi'
import { PAGE_SIZE, usePagedList } from '@/hooks/usePagedList'
import { useListControls } from '@/hooks/useListControls'
import { formatDateTime } from '@/lib/format'
import { isLiveLocalRow } from '@/lib/liveRow'

function decisionRowKey(decision: Decision): string {
  return `${decision.engine}/${decision.id}/${decision.live ? 'live' : 'archived'}`
}

export function Decisions() {
  const { t, i18n } = useTranslation()
  const controls = useListControls()
  const canWrite = useCanWrite()
  const [includeExpired, setIncludeExpired] = useState(false)
  const query = usePagedList<Decision>('decisions', controls.filters, controls.page, PAGE_SIZE, controls.isValid, includeExpired)

  function changeIncludeExpired(isChecked: boolean) {
    setIncludeExpired(isChecked)
    controls.setPage(1)
  }

  const columns = useMemo<DataTableColumn<Decision>[]>(
    () => [
      { key: 'value', header: t('decisions.columns.value'), cell: (decision) => <UntrustedText value={decision.value} /> },
      {
        key: 'engine',
        header: t('decisions.columns.engine'),
        cell: (decision) => <EngineCell engineName={decision.engine} badgeLabel={decision.live ? undefined : t('decisions.archivedBadge')} />,
      },
      { key: 'scope', header: t('decisions.columns.scope'), cell: (decision) => decision.scope },
      { key: 'type', header: t('decisions.columns.type'), cell: (decision) => decision.type },
      { key: 'origin', header: t('decisions.columns.origin'), cell: (decision) => decision.origin },
      {
        key: 'scenario',
        header: t('decisions.columns.scenario'),
        cell: (decision) => (
          <>
            <UntrustedText value={decision.scenario} />
            {decision.simulated && <Badge variant="outline" className="ml-2">{t('decisions.columns.simulated')}</Badge>}
          </>
        ),
      },
      {
        key: 'expires',
        header: t('decisions.columns.expires'),
        className: 'whitespace-nowrap',
        cell: (decision) => (decision.until ? formatDateTime(decision.until, i18n.language) : decision.duration),
      },
      ...(canWrite ? ([{
        key: 'actions',
        header: t('decisions.actions'),
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
              invalidates={[['decisions']]}
            />
          ) : null,
      }] satisfies DataTableColumn<Decision>[]) : []),
    ],
    [t, i18n.language, canWrite],
  )

  return (
    <section className="space-y-4">
      <h1 className="text-xl font-semibold">{t('decisions.title')}</h1>
      <WriteOnly>
        <BanDialog />
      </WriteOnly>
      <InfoNotice>{t('decisions.communityNotice')}</InfoNotice>
      <FilterBar values={controls.draftFilters} errors={controls.errors} onChange={controls.changeFilter} />
      <CheckboxField id="decisions-include-expired" label={t('decisions.includeExpired')} checked={includeExpired} onChange={changeIncludeExpired} />
      <PagedTableSection
        query={query}
        page={controls.page}
        onPageChange={controls.setPage}
        isLiveWindowRead={controls.isLiveWindowRead}
        caption={includeExpired ? t('decisions.captionWithExpired') : t('decisions.caption')}
        columns={columns}
        rowKey={decisionRowKey}
      />
    </section>
  )
}
