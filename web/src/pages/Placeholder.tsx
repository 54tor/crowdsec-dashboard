import { useTranslation } from 'react-i18next'

export function Placeholder({ titleKey }: { titleKey: string }) {
  const { t } = useTranslation()
  return (
    <section className="space-y-2">
      <h1 className="text-xl font-semibold">{t(titleKey)}</h1>
      <p className="text-sm text-muted-foreground">{t('common.comingSoon')}</p>
    </section>
  )
}
