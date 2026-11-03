import { useTranslation } from 'react-i18next'
import type { AllowlistListing } from '@/api/types'
import { InfoNotice, WarningNotice } from '@/components/Notice'

export function AllowlistBanners({ listing }: { listing: AllowlistListing }) {
  const { t } = useTranslation()
  return (
    <>
      {!listing.writable && <InfoNotice>{t('allowlists.readOnly')}</InfoNotice>}
      {listing.truncated && <WarningNotice>{t('allowlists.truncated')}</WarningNotice>}
    </>
  )
}
