import { useTranslation } from 'react-i18next'
import { HUB_ITEM_KINDS, type HubItemKind } from '@/api/writeApi'
import { Label } from '@/components/ui/label'

interface HubKindSelectProps {
  value: HubItemKind
  disabled: boolean
  onChange: (kind: HubItemKind) => void
}

export function HubKindSelect({ value, disabled, onChange }: HubKindSelectProps) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1">
      <Label htmlFor="install-hub-item-kind">{t('hub.installKind')}</Label>
      <select
        id="install-hub-item-kind"
        value={value}
        disabled={disabled}
        onChange={(changeEvent) => onChange(changeEvent.target.value as HubItemKind)}
        className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-base outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 md:text-sm dark:bg-input/30"
      >
        {HUB_ITEM_KINDS.map((kind) => (
          <option key={kind} value={kind}>
            {t(`hub.kinds.${kind}`)}
          </option>
        ))}
      </select>
    </div>
  )
}
