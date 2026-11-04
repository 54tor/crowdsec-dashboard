import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Machine } from '@/api/types'
import { createMachine, deleteMachine } from '@/api/writeApi'
import { CreateSecretDialog } from '@/components/CreateSecretDialog'
import { DensityToggle } from '@/components/DensityToggle'
import { HealthPageSection } from '@/components/HealthPageSection'
import { MachinesTable } from '@/components/HealthTables'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { Button } from '@/components/ui/button'
import { ValidateMachineButton } from '@/components/ValidateMachineButton'
import { WriteOnly } from '@/components/WriteOnly'
import { useCanWrite } from '@/hooks/useCanWrite'
import { HEALTH_QUERY_KEY } from '@/hooks/useReadResources'

export function Machines() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const actions = useMemo(
    () => canWrite ? ({
      header: t('machines.actions'),
      cell: (machine: Machine) => (
        <div className="flex flex-wrap items-start gap-2">
          {!machine.is_validated && <ValidateMachineButton machineId={machine.machine_id} />}
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
              request={(confirm) => deleteMachine(machine.machine_id, confirm)}
              invalidates={[HEALTH_QUERY_KEY]}
            />
          )}
        </div>
      ),
    }) : undefined,
    [t, canWrite],
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
        <>
          <DensityToggle />
          <WriteOnly>
            <CreateSecretDialog
              triggerLabel={t('machines.add')}
              labels={labels}
              createSecret={async (name) => (await createMachine(name)).password}
            />
          </WriteOnly>
        </>
      }
    >
      {(report, now) => <MachinesTable machines={report.machines} now={now} actions={actions} cardsOnMobile />}
    </HealthPageSection>
  )
}
