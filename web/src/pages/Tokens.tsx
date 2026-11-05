import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { listTokens, TOKENS_QUERY_KEY, type ApiToken } from '@/api/tokensApi'
import { ClientFilterField } from '@/components/ClientFilterField'
import { ClientFilterResults } from '@/components/ClientFilterResults'
import { CreateTokenDialog } from '@/components/CreateTokenDialog'
import { DensityToggle } from '@/components/DensityToggle'
import { ErrorNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'
import { TokensTable } from '@/components/TokensTable'
import { useClientFilter } from '@/hooks/useClientFilter'
import { formatDateTime } from '@/lib/format'

const NO_TOKENS: ApiToken[] = []

export function Tokens() {
  const { t, i18n } = useTranslation()
  const { data, error, isPending } = useQuery({ queryKey: TOKENS_QUERY_KEY, queryFn: listTokens })
  const activeTokens = data?.filter((token) => token.revoked_at === null)
  const totalTokenCount = activeTokens?.length ?? 0
  const hasRows = totalTokenCount > 0
  const tokenFilter = useClientFilter(activeTokens ?? NO_TOKENS, (token) => [
    token.name,
    t(`tokens.scopes.${token.scope}`),
    formatDateTime(token.created_at, i18n.language),
    formatDateTime(token.expires_at, i18n.language),
  ])
  return (
    <section className="space-y-4">
      <PageHeader
        title={t('tokens.title')}
        actions={
          <>
            {hasRows && <DensityToggle />}
            <CreateTokenDialog />
          </>
        }
      />
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      <ClientFilterField
        id="tokens-filter"
        label={t('clientFilter.label')}
        value={tokenFilter.filterText}
        onChange={tokenFilter.setFilterText}
        visibleCount={tokenFilter.visibleRows.length}
        totalCount={totalTokenCount}
      />
      {activeTokens && (
        <ClientFilterResults visibleCount={tokenFilter.visibleRows.length} totalCount={totalTokenCount}>
          <TokensTable tokens={tokenFilter.visibleRows} />
        </ClientFilterResults>
      )}
    </section>
  )
}
