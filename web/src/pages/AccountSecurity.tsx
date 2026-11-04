import { useQuery } from '@tanstack/react-query'
import { useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { ACCESS_RULES_QUERY_KEY, fetchAccessRules } from '@/api/accessRulesApi'
import { AccessRuleForm } from '@/components/AccessRuleForm'
import { AccessRulesTable } from '@/components/AccessRulesTable'
import { DensityToggle } from '@/components/DensityToggle'
import { InfoNotice, ErrorNotice, WarningNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { TableSkeleton } from '@/components/TableSkeleton'
import { countryLabel } from '@/lib/countryLabel'

export function AccountSecurity() {
  const { t, i18n } = useTranslation()
  const heading = useRef<HTMLHeadingElement>(null)
  const { data, error, isPending } = useQuery({ queryKey: ACCESS_RULES_QUERY_KEY, queryFn: fetchAccessRules })
  const clientCountry = data?.client_country ? ` (${countryLabel(data.client_country, i18n.language)})` : ''
  return (
    <section className="space-y-4">
      <PageHeader title={t('accountSecurity.title')} titleRef={heading} actions={<DensityToggle keepOnMobile />} />
      <InfoNotice>{t('accountSecurity.explanation')}</InfoNotice>
      <WarningNotice>{t('accountSecurity.geoNotice')}</WarningNotice>
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {data && (
        <>
          <p className="text-sm">{t('accountSecurity.clientAddress', { address: data.client_ip })}{clientCountry}</p>
          <AccessRulesTable rules={data.rules} onRuleDeleted={() => heading.current?.focus()} />
        </>
      )}
      <AccessRuleForm />
    </section>
  )
}
