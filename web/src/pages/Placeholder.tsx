import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/PageHeader'

export function Placeholder({ titleKey }: { titleKey: string }) {
  const { t } = useTranslation()
  return (
    <section className="space-y-2">
      <PageHeader title={t(titleKey)} />
      <p className="text-sm text-muted-foreground">{t('common.comingSoon')}</p>
    </section>
  )
}
