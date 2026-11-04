import type { SelectOption } from '@/components/SelectField'

interface SegmentedControlProps {
  name: string
  legend: string
  value: string
  options: readonly SelectOption[]
  onChange: (value: string) => void
}

export function SegmentedControl({ name, legend, value, options, onChange }: SegmentedControlProps) {
  return (
    <fieldset className="min-w-0 space-y-1">
      <legend className="text-sm font-medium">{legend}</legend>
      <div className="flex min-h-10 gap-0.5 rounded-md border border-input bg-background p-0.5 max-md:min-h-11">
        {options.map((option) => (
          <label key={option.value} className="flex flex-1 cursor-pointer">
            <input
              type="radio"
              name={name}
              value={option.value}
              checked={value === option.value}
              onChange={() => onChange(option.value)}
              className="peer sr-only"
            />
            <span className="flex flex-1 items-center justify-center rounded-sm px-3 text-sm text-muted-foreground peer-checked:bg-secondary peer-checked:text-foreground peer-checked:shadow-[inset_0_0_0_1px_var(--input)] peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-ring">
              {option.label}
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  )
}
