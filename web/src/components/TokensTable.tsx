import { useTranslation } from 'react-i18next'
import { revokeToken, TOKENS_QUERY_KEY, type ApiToken } from '@/api/tokensApi'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { formatDateTime } from '@/lib/format'

export function TokensTable({ tokens }: { tokens: ApiToken[] }) {
  const { t, i18n } = useTranslation()
  const columns: DataTableColumn<ApiToken>[] = [
    { key: 'name', header: t('tokens.columns.name'), cell: (token) => token.name, mobile: 'primary' },
    { key: 'scope', header: t('tokens.columns.scope'), cell: (token) => t(`tokens.scopes.${token.scope}`) },
    { key: 'createdAt', header: t('tokens.columns.createdAt'), cell: (token) => formatDateTime(token.created_at, i18n.language) },
    { key: 'expiresAt', header: t('tokens.columns.expiresAt'), cell: (token) => formatDateTime(token.expires_at, i18n.language) },
    {
      key: 'actions',
      header: t('tokens.columns.actions'),
      mobile: 'actions',
      cell: (token) => (
        <RowDeleteAction
          buttonLabel={t('tokens.revoke')}
          ariaLabel={t('tokens.revokeAria', { name: token.name })}
          title={t('tokens.revokeTitle', { name: token.name })}
          description={t('tokens.revokeDescription', { name: token.name })}
          target={token.name}
          confirmValue={String(token.token_id)}
          request={() => revokeToken(token.token_id)}
          invalidates={[TOKENS_QUERY_KEY]}
        />
      ),
    },
  ]
  return (
    <DataTable
      caption={t('tokens.tableCaption')}
      columns={columns}
      rows={tokens}
      rowKey={(token) => token.token_id}
      cardsOnMobile
      emptyMessage={t('tokens.empty')}
    />
  )
}
