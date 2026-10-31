import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Bouncer, Machine } from '@/api/types'
import { AgeCell } from '@/components/AgeCell'
import { ContactStatus } from '@/components/ContactStatus'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Badge } from '@/components/ui/badge'

export function BouncersTable({ bouncers, now }: { bouncers: Bouncer[]; now: number }) {
  const { t } = useTranslation()
  const columns = useMemo<DataTableColumn<Bouncer>[]>(
    () => [
      { key: 'name', header: t('health.columns.name'), cell: (bouncer) => bouncer.name },
      { key: 'type', header: t('health.columns.type'), cell: (bouncer) => bouncer.type },
      { key: 'version', header: t('health.columns.version'), cell: (bouncer) => bouncer.version },
      { key: 'ip', header: t('health.columns.ip'), cell: (bouncer) => bouncer.ip_address },
      { key: 'lastContact', header: t('health.columns.lastContact'), cell: (bouncer) => <AgeCell isoDate={bouncer.last_pull} now={now} /> },
      { key: 'status', header: t('health.columns.status'), cell: (bouncer) => <ContactStatus lastContact={bouncer.last_pull} now={now} revoked={bouncer.revoked} /> },
      { key: 'auth', header: t('health.columns.auth'), cell: (bouncer) => bouncer.auth_type },
    ],
    [t, now],
  )
  if (bouncers.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('health.noBouncers')}</p>
  }
  return <DataTable caption={t('health.bouncersCaption')} columns={columns} rows={bouncers} rowKey={(bouncer) => bouncer.name} />
}

export function MachinesTable({ machines, now }: { machines: Machine[]; now: number }) {
  const { t } = useTranslation()
  const columns = useMemo<DataTableColumn<Machine>[]>(
    () => [
      { key: 'name', header: t('health.columns.name'), cell: (machine) => machine.machine_id },
      { key: 'version', header: t('health.columns.version'), cell: (machine) => machine.version },
      { key: 'ip', header: t('health.columns.ip'), cell: (machine) => machine.ip_address },
      { key: 'lastContact', header: t('health.columns.lastContact'), cell: (machine) => <AgeCell isoDate={machine.last_heartbeat} now={now} /> },
      {
        key: 'status',
        header: t('health.columns.status'),
        cell: (machine) => (
          <span className="flex flex-wrap gap-1">
            <ContactStatus lastContact={machine.last_heartbeat} now={now} />
            <Badge variant="outline">{machine.is_validated ? t('health.validated') : t('health.notValidated')}</Badge>
          </span>
        ),
      },
      { key: 'auth', header: t('health.columns.auth'), cell: (machine) => machine.auth_type },
    ],
    [t, now],
  )
  if (machines.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('health.noMachines')}</p>
  }
  return <DataTable caption={t('health.machinesCaption')} columns={columns} rows={machines} rowKey={(machine) => machine.machine_id} />
}
