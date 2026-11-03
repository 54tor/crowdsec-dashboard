import { useTranslation } from 'react-i18next'
import type { AlertEvent } from '@/api/types'
import { UntrustedText } from '@/components/UntrustedText'

const APPSEC_EVENT_KEYS = [
  'rule_name',
  'message',
  'uri',
  'target_fqdn',
  'matched_zones',
  'target_host',
  'target_uri',
  'log_type',
  'remediation_cmpt_ip',
  'appsec_action',
] as const

type AppSecEventKey = (typeof APPSEC_EVENT_KEYS)[number]

type AppSecLabelKey = Exclude<AppSecEventKey, 'target_fqdn'>

function labelKeyOf(appSecKey: AppSecEventKey): AppSecLabelKey {
  return appSecKey === 'target_fqdn' ? 'target_host' : appSecKey
}

function presentAppSecKeys(meta: Record<string, string>): AppSecEventKey[] {
  return APPSEC_EVENT_KEYS.filter((appSecKey) => Object.hasOwn(meta, appSecKey))
}

function AppSecEventFields({ meta, presentKeys }: { meta: Record<string, string>; presentKeys: AppSecEventKey[] }) {
  const { t } = useTranslation()
  return (
    <dl className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-x-3 gap-y-1 rounded-lg border p-3 text-sm">
      {presentKeys.map((appSecKey) => (
        <div key={appSecKey} className="contents">
          <dt className="font-medium">{t(`appsec.fields.${labelKeyOf(appSecKey)}`)}</dt>
          <dd className="max-h-24 overflow-y-auto">
            <UntrustedText value={meta[appSecKey]} />
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function AppSecSummary({ events }: { events: AlertEvent[] }) {
  const { t } = useTranslation()
  const summarisedEvents = events
    .map((alertEvent) => ({ meta: alertEvent.meta, presentKeys: presentAppSecKeys(alertEvent.meta) }))
    .filter((summarisedEvent) => summarisedEvent.presentKeys.length > 0)
  if (summarisedEvents.length === 0) {
    return null
  }
  return (
    <section aria-labelledby="appsec-summary-title" className="space-y-2">
      <h3 id="appsec-summary-title" className="text-sm font-medium">
        {t('appsec.summaryTitle')}
      </h3>
      {summarisedEvents.map((summarisedEvent, eventPosition) => (
        <AppSecEventFields key={eventPosition} meta={summarisedEvent.meta} presentKeys={summarisedEvent.presentKeys} />
      ))}
    </section>
  )
}
