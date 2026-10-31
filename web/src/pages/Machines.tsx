import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Machine } from '@/api/types'
import { createMachine, deleteMachine } from '@/api/writeApi'
import { CreateSecretDialog } from '@/components/CreateSecretDialog'
import { HealthPageSection } from '@/components/HealthPageSection'
import { MachinesTable } from '@/components/HealthTables'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { ValidateMachineButton } from '@/components/ValidateMachineButton'
import { HEALTH_QUERY_KEY } from '@/hooks/useReadResources'

export function Machines() {
  const { t } = useTranslation()
  const actions = useMemo(
    () => ({
      header: t('machines.actions'),
      cell: (machine: Machine) => (
        <div className="flex flex-wrap items-start gap-2">
          {!machine.is_validated && <ValidateMachineButton machineId={machine.machine_id} />}
          <RowDeleteAction
            buttonLabel={t('common.delete')}
            ariaLabel={t('machines.deleteAria', { name: machine.machine_id })}
            title={t('machines.deleteTitle', { name: machine.machine_id })}
            description={t('machines.deleteDescription', { name: machine.machine_id })}
            target={machine.machine_id}
            request={(confirm) => deleteMachine(machine.machine_id, confirm)}
            invalidates={[HEALTH_QUERY_KEY]}
          />
        </div>
      ),
    }),
    [t],
  )
  const labels = {
    title: t('machines.addTitle'),
    description: t('machines.addDescription'),
    nameLabel: t('machines.nameLabel'),
    secretLabel: t('machines.secretLabel'),
  }
  return (
    <HealthPageSection
      titleKey="machines.title"
      degradedPart="machines"
      toolbar={
        <CreateSecretDialog
          triggerLabel={t('machines.add')}
          labels={labels}
          createSecret={async (name) => (await createMachine(name)).password}
        />
      }
    >
      {(report, now) => <MachinesTable machines={report.machines} now={now} actions={actions} />}
    </HealthPageSection>
  )
}
