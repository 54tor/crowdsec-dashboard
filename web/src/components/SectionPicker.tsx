import { useTranslation } from 'react-i18next'
import type { BundleSection } from '@/api/bundleApi'
import { CheckboxField } from '@/components/CheckboxField'

interface SectionPickerProps {
  idPrefix: string
  sections: readonly BundleSection[]
  selected: readonly BundleSection[]
  disabled?: boolean
  onToggle: (sectionName: BundleSection) => void
}

export function SectionPicker({ idPrefix, sections, selected, disabled, onToggle }: SectionPickerProps) {
  const { t } = useTranslation()
  return (
    <fieldset className="space-y-2" disabled={disabled}>
      <legend className="text-sm font-medium">{t('bundle.sectionsLegend')}</legend>
      {sections.map((sectionName) => (
        <CheckboxField
          key={sectionName}
          id={`${idPrefix}-${sectionName}`}
          label={t(`bundle.sections.${sectionName}`)}
          checked={selected.includes(sectionName)}
          onChange={() => onToggle(sectionName)}
        />
      ))}
    </fieldset>
  )
}
