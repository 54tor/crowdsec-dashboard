import { useTranslation } from 'react-i18next'

export function BrandMark() {
  const { t } = useTranslation()
  return (
    <div className="flex items-center gap-2.5">
      <img src="/crowdsec-logo.png" alt="" width={617} height={416} className="h-7 w-auto" />
      <span className="font-condensed text-sm leading-tight font-semibold">{t('app.title')}</span>
    </div>
  )
}
