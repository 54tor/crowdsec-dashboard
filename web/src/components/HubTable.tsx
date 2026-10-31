import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { HubItem } from '@/api/types'
import { removeCollection } from '@/api/writeApi'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { HUB_QUERY_KEY } from '@/hooks/useReadResources'
import { useReloadRequired } from '@/hooks/useReloadRequired'

export function HubTable({ items }: { items: HubItem[] }) {
  const { t } = useTranslation()
  const { markReloadRequired } = useReloadRequired()
  const columns = useMemo<DataTableColumn<HubItem>[]>(
    () => [
      { key: 'type', header: t('hub.columns.type'), cell: (hubItem) => hubItem.type },
      { key: 'name', header: t('hub.columns.name'), cell: (hubItem) => hubItem.name },
      { key: 'status', header: t('hub.columns.status'), cell: (hubItem) => hubItem.status },
      { key: 'version', header: t('hub.columns.version'), cell: (hubItem) => hubItem.local_version },
      { key: 'description', header: t('hub.columns.description'), cell: (hubItem) => hubItem.description },
      {
        key: 'actions',
        header: t('hub.columns.actions'),
        cell: (hubItem) =>
          hubItem.type === 'collections' && (
            <RowDeleteAction
              buttonLabel={t('hub.remove')}
              ariaLabel={t('hub.removeAria', { name: hubItem.name })}
              title={t('hub.removeTitle', { name: hubItem.name })}
              description={t('hub.removeDescription', { name: hubItem.name })}
              target={hubItem.name}
              request={(confirm) => removeCollection(hubItem.name, confirm)}
              invalidates={[HUB_QUERY_KEY]}
              onDeleted={markReloadRequired}
            />
          ),
      },
    ],
    [t, markReloadRequired],
  )
  return <DataTable caption={t('hub.caption')} columns={columns} rows={items} rowKey={(hubItem) => `${hubItem.type}/${hubItem.name}`} />
}
