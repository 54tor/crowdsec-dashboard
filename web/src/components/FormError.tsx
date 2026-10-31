import { useEffect, useRef } from 'react'
import { errorMessage } from '@/i18n'

export function FormError({ failure }: { failure: unknown }) {
  const alertReference = useRef<HTMLParagraphElement>(null)

  useEffect(() => {
    alertReference.current?.focus()
  }, [])

  return (
    <p ref={alertReference} role="alert" tabIndex={-1} className="text-sm text-destructive outline-none">
      {errorMessage(failure)}
    </p>
  )
}
