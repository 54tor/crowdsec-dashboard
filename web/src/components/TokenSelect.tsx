import { SelectField, type SelectOption } from '@/components/SelectField'

interface TokenSelectProps {
  id: string
  label: string
  value: string
  options: readonly SelectOption[]
  onChange: (chosenValue: string) => void
  disabled?: boolean
  title?: string
}

export function TokenSelect(tokenSelectProps: TokenSelectProps) {
  return <SelectField {...tokenSelectProps} />
}
