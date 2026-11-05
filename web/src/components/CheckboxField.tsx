import type { ChangeEvent } from 'react'

interface CheckboxFieldProps {
  id: string
  label: string
  checked: boolean
  onChange: (isChecked: boolean) => void
  disabled?: boolean
  describedBy?: string
}

export function CheckboxField({ id, label, checked, onChange, disabled, describedBy }: CheckboxFieldProps) {
  return (
    <label htmlFor={id} className="flex min-h-10 cursor-pointer items-center has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-60 gap-2 text-sm max-md:min-h-11">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        aria-describedby={describedBy}
        onChange={(changeEvent: ChangeEvent<HTMLInputElement>) => onChange(changeEvent.target.checked)}
        className="size-5 accent-primary focus-ring"
      />
      {label}
    </label>
  )
}
