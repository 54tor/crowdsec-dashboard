import { FieldMessages } from '@/components/FieldMessages'
import { FIELD_CONTROL_CLASS_NAME } from '@/components/ui/fieldControl'
import { Label } from '@/components/ui/label'
import { describedByIds } from '@/lib/fieldDescription'

export interface SelectOption {
  value: string
  label: string
}

interface SelectFieldProps {
  id: string
  label: string
  value: string
  options: readonly SelectOption[]
  onChange: (value: string) => void
  hint?: string
  error?: string | null
  disabled?: boolean
  title?: string
}

export function SelectField({ id, label, value, options, onChange, hint, error, disabled, title }: SelectFieldProps) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        title={title}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedByIds(id, hint, error)}
        onChange={(changeEvent) => onChange(changeEvent.target.value)}
        className={FIELD_CONTROL_CLASS_NAME}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      <FieldMessages fieldId={id} hint={hint} error={error} />
    </div>
  )
}
