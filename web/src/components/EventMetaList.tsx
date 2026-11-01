import { useTranslation } from 'react-i18next'
import { UntrustedText } from '@/components/UntrustedText'

export function EventMetaList({ meta }: { meta: Record<string, string> }) {
  const { t } = useTranslation()
  const metaEntries = Object.entries(meta)
  if (metaEntries.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('alertDetail.noMeta')}</p>
  }
  return (
    <dl className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-x-3 gap-y-1 text-sm">
      {metaEntries.map(([metaKey, metaValue]) => (
        <div key={metaKey} className="contents">
          <dt className="font-medium">
            <UntrustedText value={metaKey} />
          </dt>
          <dd>
            <UntrustedText value={metaValue} />
          </dd>
        </div>
      ))}
    </dl>
  )
}
