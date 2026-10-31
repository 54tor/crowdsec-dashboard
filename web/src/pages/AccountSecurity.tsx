import { useQuery } from '@tanstack/react-query'
import { useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { ACCESS_RULES_QUERY_KEY, fetchAccessRules } from '@/api/accessRulesApi'
import { AccessRuleForm } from '@/components/AccessRuleForm'
import { AccessRulesTable } from '@/components/AccessRulesTable'
import { InfoNotice, ErrorNotice, WarningNotice } from '@/components/Notice'
import { TableSkeleton } from '@/components/TableSkeleton'
import { countryLabel } from '@/lib/countryLabel'

export function AccountSecurity() {
  const { t, i18n } = useTranslation()
  const heading = useRef<HTMLHeadingElement>(null)
  const { data, error, isPending } = useQuery({ queryKey: ACCESS_RULES_QUERY_KEY, queryFn: fetchAccessRules })
  const clientCountry = data?.client_country ? ` (${countryLabel(data.client_country, i18n.language)})` : ''
  return (
    <section className="space-y-4">
      <h1 ref={heading} tabIndex={-1} className="text-xl font-semibold outline-none">
        {t('accountSecurity.title')}
      </h1>
      <InfoNotice>{t('accountSecurity.explanation')}</InfoNotice>
      <WarningNotice>{t('accountSecurity.geoNotice')}</WarningNotice>
      {error && <ErrorNotice error={error} />}
      {isPending && <TableSkeleton />}
      {data && (
        <>
          <p className="text-sm">{t('accountSecurity.clientAddress', { address: data.client_ip })}{clientCountry}</p>
          {data.rules.length === 0 ? (
            <p>{t('accountSecurity.emptyAllowsAll')}</p>
          ) : (
            <AccessRulesTable rules={data.rules} onRuleDeleted={() => heading.current?.focus()} />
          )}
        </>
      )}
      <AccessRuleForm />
    </section>
  )
}
