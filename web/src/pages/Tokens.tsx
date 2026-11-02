import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { listTokens, TOKENS_QUERY_KEY } from '@/api/tokensApi'
import { CreateTokenDialog } from '@/components/CreateTokenDialog'
import { ErrorNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { TokensTable } from '@/components/TokensTable'

export function Tokens() {
  const { t } = useTranslation()
  const { data, error, isPending } = useQuery({ queryKey: TOKENS_QUERY_KEY, queryFn: listTokens })
  const activeTokens = data?.filter((token) => token.revoked_at === null)
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">{t('tokens.title')}</h1>
        <CreateTokenDialog />
      </div>
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {activeTokens && (activeTokens.length === 0 ? <p>{t('tokens.empty')}</p> : <TokensTable tokens={activeTokens} />)}
    </section>
  )
}
