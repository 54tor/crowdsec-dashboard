import type { ComponentProps } from 'react'
import { FieldMessages } from '@/components/FieldMessages'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { describedByIds } from '@/lib/fieldDescription'

interface FormFieldProps extends Omit<ComponentProps<typeof Input>, 'id'> {
  id: string
  label: string
  hint?: string
  error?: string | null
}

export function FormField({ id, label, hint, error, ...inputProps }: FormFieldProps) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        autoComplete="off"
        spellCheck={false}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedByIds(id, hint, error)}
        {...inputProps}
      />
      <FieldMessages fieldId={id} hint={hint} error={error} />
    </div>
  )
}
