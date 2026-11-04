import { useTranslation } from 'react-i18next'
import { HUB_ITEM_KINDS, type HubItemKind } from '@/api/writeApi'
import { SelectField } from '@/components/SelectField'

interface HubKindSelectProps {
  value: HubItemKind
  disabled: boolean
  onChange: (kind: HubItemKind) => void
}

export function HubKindSelect({ value, disabled, onChange }: HubKindSelectProps) {
  const { t } = useTranslation()
  return (
    <SelectField
      id="install-hub-item-kind"
      label={t('hub.installKind')}
      value={value}
      disabled={disabled}
      options={HUB_ITEM_KINDS.map((kind) => ({ value: kind, label: t(`hub.kinds.${kind}`) }))}
      onChange={(chosenKind) => onChange(chosenKind as HubItemKind)}
    />
  )
}
