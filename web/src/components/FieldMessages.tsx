import { errorIdFor, hintIdFor } from '@/lib/fieldDescription'

interface FieldMessagesProps {
  fieldId: string
  hint?: string
  error?: string | null
}

export function FieldMessages({ fieldId, hint, error }: FieldMessagesProps) {
  return (
    <>
      {hint && (
        <p id={hintIdFor(fieldId)} className="text-xs text-muted-foreground">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorIdFor(fieldId)} className="text-sm text-critical">
          {error}
        </p>
      )}
    </>
  )
}
