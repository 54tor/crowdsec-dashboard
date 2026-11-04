import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { HubItem } from '@/api/types'
import { isHubItemKind, removeHubItem } from '@/api/writeApi'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { Badge } from '@/components/ui/badge'
import { useCanWrite } from '@/hooks/useCanWrite'
import { HUB_QUERY_KEY } from '@/hooks/useReadResources'
import { isTimeoutError } from '@/lib/apiErrors'
import { useReloadRequired } from '@/hooks/useReloadRequired'

export function HubTable({ items }: { items: HubItem[] }) {
  const { t } = useTranslation()
  const { markReloadRequired } = useReloadRequired()
  const canWrite = useCanWrite()
  const columns = useMemo<DataTableColumn<HubItem>[]>(
    () => [
      { key: 'type', header: t('hub.columns.type'), noWrap: true, cell: (hubItem) => hubItem.type },
      { key: 'name', header: t('hub.columns.name'), noWrap: true, cell: (hubItem) => hubItem.name },
      {
        key: 'status',
        header: t('hub.columns.status'),
        noWrap: true,
        cell: (hubItem) => <Badge variant={hubItem.status === 'enabled' ? 'nominal' : 'outline'}>{hubItem.status}</Badge>,
      },
      { key: 'version', header: t('hub.columns.version'), noWrap: true, cell: (hubItem) => hubItem.local_version },
      { key: 'description', header: t('hub.columns.description'), cell: (hubItem) => hubItem.description },
      ...(canWrite ? ([{
        key: 'actions',
        header: t('hub.columns.actions'),
        cell: (hubItem) => {
          const kind = hubItem.type
          if (!isHubItemKind(kind)) {
            return null
          }
          return (
            <RowDeleteAction
              buttonLabel={t('hub.remove')}
              ariaLabel={t('hub.removeAria', { name: hubItem.name })}
              title={t('hub.removeTitle', { name: hubItem.name })}
              description={`${t('hub.removeDescription', { name: hubItem.name })} ${t('hub.removeAppSecWarning')}`}
              target={hubItem.name}
              request={(confirm) => removeHubItem(kind, hubItem.name, confirm)}
              invalidates={[HUB_QUERY_KEY]}
              onDeleted={markReloadRequired}
              onFailed={(failure) => isTimeoutError(failure) && markReloadRequired()}
            />
          )
        },
      }] satisfies DataTableColumn<HubItem>[]) : []),
    ],
    [t, markReloadRequired, canWrite],
  )
  return <DataTable caption={t('hub.caption')} columns={columns} rows={items} rowKey={(hubItem) => `${hubItem.type}/${hubItem.name}`} />
}
