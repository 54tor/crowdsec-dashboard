import type { ChangeEvent } from 'react'

interface CheckboxFieldProps {
  id: string
  label: string
  checked: boolean
  onChange: (isChecked: boolean) => void
}

export function CheckboxField({ id, label, checked, onChange }: CheckboxFieldProps) {
  return (
    <div className="flex min-h-10 items-center gap-2 max-md:min-h-11">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={(changeEvent: ChangeEvent<HTMLInputElement>) => onChange(changeEvent.target.checked)}
        className="size-5 accent-primary focus-ring"
      />
      <label htmlFor={id} className="text-sm">
        {label}
      </label>
    </div>
  )
}
