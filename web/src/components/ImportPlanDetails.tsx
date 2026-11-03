import { useTranslation } from 'react-i18next'
import type { ImportPlan } from '@/api/bundleApi'
import { ConfigFileDiffs } from '@/components/ConfigFileDiffs'
import { UntrustedText } from '@/components/UntrustedText'
import { translateBundleCode } from '@/lib/bundleCodes'

const MAX_LISTED_ITEMS = 50

function BoundedList<Item>({ title, items, render }: { title: string; items: readonly Item[]; render: (item: Item) => string }) {
  const { t } = useTranslation()
  if (items.length === 0) {
    return null
  }
  return (
    <div>
      <h4 className="text-sm font-medium">
        {title} ({items.length})
      </h4>
      <ul className="list-disc pl-4 text-sm">
        {items.slice(0, MAX_LISTED_ITEMS).map((item, itemIndex) => {
          const label = render(item)
          return (
            <li key={`${itemIndex}-${label}`}>
              <UntrustedText value={label} />
            </li>
          )
        })}
      </ul>
      {items.length > MAX_LISTED_ITEMS && <p className="text-xs text-muted-foreground">{t('bundle.moreItems', { count: items.length - MAX_LISTED_ITEMS })}</p>}
    </div>
  )
}

export function ImportPlanDetails({ plan }: { plan: ImportPlan }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-3">
      <BoundedList title={t('bundle.sections.hub')} items={plan.hub} render={(action) => `${action.name} ${action.version}`.trim()} />
      <BoundedList title={t('bundle.sections.decisions')} items={plan.decisions} render={(action) => `${action.scope} ${action.value} — ${action.scenario}`} />
      <BoundedList title={t('bundle.sections.alerts')} items={plan.alerts} render={(action) => `${action.scope} ${action.value} — ${action.scenario}`} />
      <BoundedList
        title={t('bundle.skippedTitle')}
        items={plan.skipped}
        render={(item) => `${t(`bundle.sections.${item.section}`)} — ${item.target} (${translateBundleCode(t, 'skipReasons', item.reason)})`}
      />
      <ConfigFileDiffs files={plan.config} />
    </div>
  )
}
