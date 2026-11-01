import type { ChangeEvent } from 'react'

interface CheckboxFieldProps {
  id: string
  label: string
  checked: boolean
  onChange: (isChecked: boolean) => void
}

export function CheckboxField({ id, label, checked, onChange }: CheckboxFieldProps) {
  return (
    <div className="flex items-center gap-2">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={(changeEvent: ChangeEvent<HTMLInputElement>) => onChange(changeEvent.target.checked)}
        className="size-4"
      />
      <label htmlFor={id} className="text-sm">
        {label}
      </label>
    </div>
  )
}
