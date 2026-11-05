import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Machine } from '@/api/types'
import { createMachine, deleteMachine } from '@/api/writeApi'
import { ClientFilterField } from '@/components/ClientFilterField'
import { ClientFilterResults } from '@/components/ClientFilterResults'
import { CreateSecretDialog } from '@/components/CreateSecretDialog'
import { EngineListSection } from '@/components/EngineListSection'
import { MachinesTable, type RowActions } from '@/components/HealthTables'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { Button } from '@/components/ui/button'
import { ValidateMachineButton } from '@/components/ValidateMachineButton'
import { WriteOnly } from '@/components/WriteOnly'
import { useCanWrite } from '@/hooks/useCanWrite'
import { useClientFilter } from '@/hooks/useClientFilter'
import { useEngineTarget } from '@/hooks/useEngineTarget'
import { HEALTH_QUERY_KEY, MACHINES_QUERY_KEY, useMachines } from '@/hooks/useReadResources'

interface FilteredMachinesProps {
  engineName: string
  machines: Machine[]
  now: number
  actions?: RowActions<Machine>
}

function FilteredMachines({ engineName, machines, now, actions }: FilteredMachinesProps) {
  const { t } = useTranslation()
  const machineFilter = useClientFilter(machines, (machine) => [
    machine.machine_id,
    machine.self ? t('health.self') : '',
    machine.version,
    machine.ip_address,
    machine.is_validated ? t('health.validated') : t('health.notValidated'),
    machine.auth_type,
  ])
  return (
    <>
      <ClientFilterField
        id="machines-filter"
        label={t('clientFilter.label')}
        value={machineFilter.filterText}
        onChange={machineFilter.setFilterText}
        visibleCount={machineFilter.visibleRows.length}
        totalCount={machines.length}
      />
      <ClientFilterResults visibleCount={machineFilter.visibleRows.length} totalCount={machines.length}>
        <MachinesTable engineName={engineName} machines={machineFilter.visibleRows} now={now} actions={actions} cardsOnMobile />
      </ClientFilterResults>
    </>
  )
}

export function Machines() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const [engineName, setEngineName] = useEngineTarget()
  const machinesQuery = useMachines(engineName)
  const invalidatedKeys = useMemo(() => [[...MACHINES_QUERY_KEY, engineName], HEALTH_QUERY_KEY], [engineName])
  const actions = useMemo(
    () => canWrite ? ({
      header: t('machines.actions'),
      cell: (machine: Machine) => (
        <div className="flex flex-wrap items-start gap-2">
          {!machine.is_validated && <ValidateMachineButton machineId={machine.machine_id} engineName={engineName} />}
          {machine.self ? (
            <div className="flex flex-col gap-1">
              <Button
                type="button"
                variant="destructiveOutline"
                size="sm"
                disabled
                aria-label={t('machines.deleteAria', { name: machine.machine_id })}
                aria-describedby={`self-delete-reason-${machine.machine_id}`}
              >
                {t('common.delete')}
              </Button>
              <span id={`self-delete-reason-${machine.machine_id}`} className="text-xs text-muted-foreground">
                {t('machines.selfDeleteReason')}
              </span>
            </div>
          ) : (
            <RowDeleteAction
              buttonLabel={t('common.delete')}
              ariaLabel={t('machines.deleteAria', { name: machine.machine_id })}
              title={t('machines.deleteTitle', { name: machine.machine_id })}
              description={t('machines.deleteDescription', { name: machine.machine_id })}
              target={machine.machine_id}
              engineName={engineName}
              request={(confirm) => deleteMachine(machine.machine_id, confirm, engineName)}
              invalidates={invalidatedKeys}
            />
          )}
        </div>
      ),
    }) : undefined,
    [t, canWrite, engineName, invalidatedKeys],
  )
  const labels = {
    title: t('machines.addTitle'),
    description: t('machines.addDescription'),
    nameLabel: t('machines.nameLabel'),
    secretLabel: t('machines.secretLabel'),
  }
  return (
    <EngineListSection
      title={t('machines.title')}
      selectId="machines-engine"
      engineName={engineName}
      onEngineChange={setEngineName}
      query={machinesQuery}
      toolbar={
        <WriteOnly>
          <CreateSecretDialog
            triggerLabel={t('machines.add')}
            labels={labels}
            engineName={engineName}
            invalidates={invalidatedKeys}
            createSecret={async (name) => (await createMachine(name, engineName)).password}
          />
        </WriteOnly>
      }
    >
      {(machines, now) => <FilteredMachines engineName={engineName} machines={machines} now={now} actions={actions} />}
    </EngineListSection>
  )
}
