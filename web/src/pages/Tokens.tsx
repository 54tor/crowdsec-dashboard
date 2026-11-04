import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { listTokens, TOKENS_QUERY_KEY } from '@/api/tokensApi'
import { CreateTokenDialog } from '@/components/CreateTokenDialog'
import { DensityToggle } from '@/components/DensityToggle'
import { ErrorNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'
import { TokensTable } from '@/components/TokensTable'

export function Tokens() {
  const { t } = useTranslation()
  const { data, error, isPending } = useQuery({ queryKey: TOKENS_QUERY_KEY, queryFn: listTokens })
  const activeTokens = data?.filter((token) => token.revoked_at === null)
  return (
    <section className="space-y-4">
      <PageHeader
        title={t('tokens.title')}
        actions={
          <>
            <DensityToggle />
            <CreateTokenDialog />
          </>
        }
      />
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {activeTokens && <TokensTable tokens={activeTokens} />}
    </section>
  )
}
