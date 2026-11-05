import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Bouncer } from '@/api/types'
import { createBouncer, deleteBouncer } from '@/api/writeApi'
import { ClientFilterField } from '@/components/ClientFilterField'
import { ClientFilterResults } from '@/components/ClientFilterResults'
import { CreateSecretDialog } from '@/components/CreateSecretDialog'
import { EngineListSection } from '@/components/EngineListSection'
import { BouncersTable, type RowActions } from '@/components/HealthTables'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { WriteOnly } from '@/components/WriteOnly'
import { useCanWrite } from '@/hooks/useCanWrite'
import { useClientFilter } from '@/hooks/useClientFilter'
import { useEngineTarget } from '@/hooks/useEngineTarget'
import { BOUNCERS_QUERY_KEY, HEALTH_QUERY_KEY, useBouncers } from '@/hooks/useReadResources'

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
  const [engineName, setEngineName] = useEngineTarget()
  const bouncersQuery = useBouncers(engineName)
  const invalidatedKeys = useMemo(() => [[...BOUNCERS_QUERY_KEY, engineName], HEALTH_QUERY_KEY], [engineName])
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
          engineName={engineName}
          request={(confirm) => deleteBouncer(bouncer.name, confirm, engineName)}
          invalidates={invalidatedKeys}
        />
      ),
    }) : undefined,
    [t, canWrite, engineName, invalidatedKeys],
  )
  const labels = {
    title: t('bouncers.addTitle'),
    description: t('bouncers.addDescription'),
    nameLabel: t('bouncers.nameLabel'),
    secretLabel: t('bouncers.secretLabel'),
  }
  return (
    <EngineListSection
      title={t('bouncers.title')}
      selectId="bouncers-engine"
      engineName={engineName}
      onEngineChange={setEngineName}
      query={bouncersQuery}
      toolbar={
        <WriteOnly>
          <CreateSecretDialog
            triggerLabel={t('bouncers.add')}
            labels={labels}
            engineName={engineName}
            invalidates={invalidatedKeys}
            createSecret={async (name) => (await createBouncer(name, engineName)).key}
          />
        </WriteOnly>
      }
    >
      {(bouncers, now) => <FilteredBouncers bouncers={bouncers} now={now} actions={actions} />}
    </EngineListSection>
  )
}
