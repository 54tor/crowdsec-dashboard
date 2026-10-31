import type { ComponentProps } from 'react'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

interface LabelledInputProps extends Omit<ComponentProps<typeof Input>, 'id'> {
  id: string
  label: string
}

export function LabelledInput({ id, label, ...inputProps }: LabelledInputProps) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} required {...inputProps} />
    </div>
  )
}
