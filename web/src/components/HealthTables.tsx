import { useMemo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { LOCAL_ENGINE_NAME } from '@/api/engineQuery'
import type { Bouncer, Machine } from '@/api/types'
import { AgeCell } from '@/components/AgeCell'
import { ContactStatus } from '@/components/ContactStatus'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Badge } from '@/components/ui/badge'

export interface RowActions<Row> {
  header: string
  cell: (row: Row) => ReactNode
}

interface BouncersTableProps {
  bouncers: Bouncer[]
  now: number
  actions?: RowActions<Bouncer>
  cardsOnMobile?: boolean
}

interface MachinesTableProps {
  machines: Machine[]
  now: number
  actions?: RowActions<Machine>
  cardsOnMobile?: boolean
  engineName?: string
}

export function BouncersTable({ bouncers, now, actions, cardsOnMobile = false }: BouncersTableProps) {
  const { t } = useTranslation()
  const columns = useMemo<DataTableColumn<Bouncer>[]>(
    () => [
      { key: 'name', header: t('health.columns.name'), cell: (bouncer) => bouncer.name, mobile: 'primary', noWrap: true },
      { key: 'type', header: t('health.columns.type'), noWrap: true, cell: (bouncer) => bouncer.type },
      { key: 'version', header: t('health.columns.version'), noWrap: true, cell: (bouncer) => bouncer.version },
      { key: 'ip', header: t('health.columns.ip'), cell: (bouncer) => bouncer.ip_address, className: 'font-mono', noWrap: true },
      { key: 'lastContact', header: t('health.columns.lastContact'), noWrap: true, cell: (bouncer) => <AgeCell isoDate={bouncer.last_pull} now={now} /> },
      { key: 'status', header: t('health.columns.status'), noWrap: true, cell: (bouncer) => <ContactStatus lastContact={bouncer.last_pull} now={now} revoked={bouncer.revoked} /> },
      { key: 'auth', header: t('health.columns.auth'), noWrap: true, cell: (bouncer) => bouncer.auth_type },
      ...(actions ? [{ key: 'actions', header: actions.header, cell: actions.cell, mobile: 'actions' as const }] : []),
    ],
    [t, now, actions],
  )
  return (
    <DataTable
      caption={t('health.bouncersCaption')}
      columns={columns}
      rows={bouncers}
      rowKey={(bouncer) => bouncer.name}
      cardsOnMobile={cardsOnMobile}
      emptyMessage={t('health.noBouncers')}
    />
  )
}

export function MachinesTable({ machines, now, actions, cardsOnMobile = false, engineName = LOCAL_ENGINE_NAME }: MachinesTableProps) {
  const { t } = useTranslation()
  const columns = useMemo<DataTableColumn<Machine>[]>(
    () => [
      {
        key: 'name',
        header: t('health.columns.name'),
        mobile: 'primary',
        noWrap: true,
        cell: (machine) => (
          <span className="flex flex-wrap items-center gap-1">
            {machine.machine_id}
            {machine.self && <Badge variant="outline">{t('health.self')}</Badge>}
          </span>
        ),
      },
      { key: 'version', header: t('health.columns.version'), noWrap: true, cell: (machine) => machine.version },
      { key: 'ip', header: t('health.columns.ip'), cell: (machine) => machine.ip_address, className: 'font-mono', noWrap: true },
      { key: 'lastContact', header: t('health.columns.lastContact'), noWrap: true, cell: (machine) => (machine.self ? '—' : <AgeCell isoDate={machine.last_heartbeat} now={now} />) },
      {
        key: 'status',
        header: t('health.columns.status'),
        noWrap: true,
        cell: (machine) => (
          <span className="flex flex-wrap gap-1">
            {!machine.self && <ContactStatus lastContact={machine.last_heartbeat} now={now} />}
            <Badge variant="outline">{machine.is_validated ? t('health.validated') : t('health.notValidated')}</Badge>
          </span>
        ),
      },
      { key: 'auth', header: t('health.columns.auth'), noWrap: true, cell: (machine) => machine.auth_type },
      ...(actions ? [{ key: 'actions', header: actions.header, cell: actions.cell, mobile: 'actions' as const }] : []),
    ],
    [t, now, actions],
  )
  return (
    <DataTable
      caption={t('health.machinesCaption')}
      columns={columns}
      rows={machines}
      rowKey={(machine) => `${engineName}/${machine.machine_id}`}
      cardsOnMobile={cardsOnMobile}
      emptyMessage={t('health.noMachines')}
    />
  )
}
