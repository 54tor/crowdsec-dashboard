import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback, useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { allowlistsQueryKey, listAllowlists } from '@/api/allowlistsApi'
import type { AllowlistListing, AllowlistMutation } from '@/api/types'
import { useAuth } from '@/auth/useAuth'
import { AllowlistBanners } from '@/components/AllowlistBanners'
import { AllowlistEngineSelect } from '@/components/AllowlistEngineSelect'
import { AllowlistSection } from '@/components/AllowlistSection'
import { CreateAllowlistDialog } from '@/components/CreateAllowlistDialog'
import { DensityToggle } from '@/components/DensityToggle'
import { EmptyState } from '@/components/EmptyState'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'
import { useCanWrite } from '@/hooks/useCanWrite'
import { visibleNavItems } from '@/routes'

const DEFAULT_ENGINE_NAME = 'local'
const CONFIG_PATH = '/config'

function ConfigPageNote() {
  const { accountRole } = useAuth()
  const canOpenConfig = visibleNavItems(accountRole).some((navItem) => navItem.path === CONFIG_PATH)
  if (!canOpenConfig) {
    return null
  }
  return (
    <p className="text-sm text-muted-foreground">
      <Trans i18nKey="allowlists.configNote" components={{ configLink: <Link to={CONFIG_PATH} className="underline underline-offset-4" /> }} />
    </p>
  )
}

function listingOf(mutation: AllowlistMutation): AllowlistListing {
  return { engine: mutation.engine, writable: mutation.writable, truncated: mutation.truncated, allowlists: mutation.allowlists }
}

interface AllowlistListingViewProps {
  listing: AllowlistListing
  isWritable: boolean
  onWritten: (mutation: AllowlistMutation) => void
}

function AllowlistListingView({ listing, isWritable, onWritten }: AllowlistListingViewProps) {
  const { t } = useTranslation()
  return (
    <>
      <AllowlistBanners listing={listing} />
      {isWritable && <CreateAllowlistDialog engineName={listing.engine} onWritten={onWritten} />}
      {listing.allowlists.length === 0 && <EmptyState message={t('allowlists.empty')} />}
      {listing.allowlists.map((allowlist) => (
        <AllowlistSection key={`${listing.engine}/${allowlist.name}`} engineName={listing.engine} allowlist={allowlist} isWritable={isWritable} onWritten={onWritten} />
      ))}
    </>
  )
}

export function Allowlists() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const [engineName, setEngineName] = useState(DEFAULT_ENGINE_NAME)
  const [isRefreshFailed, setIsRefreshFailed] = useState(false)
  const listingQuery = useQuery({ queryKey: allowlistsQueryKey(engineName), queryFn: () => listAllowlists(engineName) })

  const handleWritten = useCallback(
    (mutation: AllowlistMutation) => {
      setIsRefreshFailed(!mutation.refreshed)
      if (mutation.refreshed) {
        queryClient.setQueryData<AllowlistListing>(allowlistsQueryKey(engineName), listingOf(mutation))
        return
      }
      void queryClient.invalidateQueries({ queryKey: allowlistsQueryKey(engineName) })
    },
    [queryClient, engineName],
  )

  function selectEngine(selectedEngineName: string) {
    setEngineName(selectedEngineName)
    setIsRefreshFailed(false)
  }

  const listing = listingQuery.data
  return (
    <section className="space-y-4">
      <PageHeader title={t('allowlists.title')} description={t('allowlists.intro')} actions={<DensityToggle />} />
      <ConfigPageNote />
      <AllowlistEngineSelect value={engineName} onChange={selectEngine} />
      {isRefreshFailed && <WarningNotice>{t('allowlists.refreshFailed')}</WarningNotice>}
      {listingQuery.error && <ErrorNotice error={listingQuery.error} />}
      {listingQuery.isPending && <TableSkeleton />}
      {listing && <AllowlistListingView listing={listing} isWritable={canWrite && listing.writable} onWritten={handleWritten} />}
    </section>
  )
}
