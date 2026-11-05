import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Bouncer } from '@/api/types'
import { createBouncer, deleteBouncer } from '@/api/writeApi'
import { ClientFilterField } from '@/components/ClientFilterField'
import { ClientFilterResults } from '@/components/ClientFilterResults'
import { CreateSecretDialog } from '@/components/CreateSecretDialog'
import { HealthPageSection } from '@/components/HealthPageSection'
import { BouncersTable, type RowActions } from '@/components/HealthTables'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { WriteOnly } from '@/components/WriteOnly'
import { useCanWrite } from '@/hooks/useCanWrite'
import { useClientFilter } from '@/hooks/useClientFilter'
import { HEALTH_QUERY_KEY } from '@/hooks/useReadResources'

interface FilteredBouncersProps {
  bouncers: Bouncer[]
  now: number
  actions?: RowActions<Bouncer>
}

function bouncerSearchTexts(bouncer: Bouncer): string[] {
  return [bouncer.name, bouncer.type, bouncer.version, bouncer.ip_address, bouncer.auth_type]
}

function FilteredBouncers({ bouncers, now, actions }: FilteredBouncersProps) {
  const { t } = useTranslation()
  const bouncerFilter = useClientFilter(bouncers, bouncerSearchTexts)
  return (
    <>
      <ClientFilterField
        id="bouncers-filter"
        label={t('clientFilter.label')}
        value={bouncerFilter.filterText}
        onChange={bouncerFilter.setFilterText}
        visibleCount={bouncerFilter.visibleRows.length}
        totalCount={bouncers.length}
      />
      <ClientFilterResults visibleCount={bouncerFilter.visibleRows.length} totalCount={bouncers.length}>
        <BouncersTable bouncers={bouncerFilter.visibleRows} now={now} actions={actions} cardsOnMobile />
      </ClientFilterResults>
    </>
  )
}

export function Bouncers() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const actions = useMemo(
    () => canWrite ? ({
      header: t('bouncers.actions'),
      cell: (bouncer: Bouncer) => (
        <RowDeleteAction
          buttonLabel={t('common.delete')}
          ariaLabel={t('bouncers.deleteAria', { name: bouncer.name })}
          title={t('bouncers.deleteTitle', { name: bouncer.name })}
          description={t('bouncers.deleteDescription', { name: bouncer.name })}
          target={bouncer.name}
          request={(confirm) => deleteBouncer(bouncer.name, confirm)}
          invalidates={[HEALTH_QUERY_KEY]}
        />
      ),
    }) : undefined,
    [t, canWrite],
  )
  const labels = {
    title: t('bouncers.addTitle'),
    description: t('bouncers.addDescription'),
    nameLabel: t('bouncers.nameLabel'),
    secretLabel: t('bouncers.secretLabel'),
  }
  return (
    <HealthPageSection
      titleKey="bouncers.title"
      degradedPart="bouncers"
      hasRows={(report) => report.bouncers.length > 0}
      toolbar={
        <WriteOnly>
          <CreateSecretDialog
            triggerLabel={t('bouncers.add')}
            labels={labels}
            createSecret={async (name) => (await createBouncer(name)).key}
          />
        </WriteOnly>
      }
    >
      {(report, now) => <FilteredBouncers bouncers={report.bouncers} now={now} actions={actions} />}
    </HealthPageSection>
  )
}
