import { Label } from '@/components/ui/label'

interface TokenSelectProps {
  id: string
  label: string
  value: string
  options: { value: string; label: string }[]
  onChange: (chosenValue: string) => void
  disabled?: boolean
  title?: string
}

export function TokenSelect({ id, label, value, options, onChange, disabled, title }: TokenSelectProps) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        title={title}
        onChange={(changeEvent) => onChange(changeEvent.target.value)}
        className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  )
}
