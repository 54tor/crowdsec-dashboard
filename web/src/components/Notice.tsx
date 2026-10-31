import { Info, TriangleAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { errorMessage } from '@/i18n'

export function InfoNotice({ children }: { children: ReactNode }) {
  return (
    <Alert role="status">
      <Info aria-hidden="true" />
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  )
}

export function WarningNotice({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <Alert role="status" className="border-amber-600">
      <TriangleAlert aria-hidden="true" />
      {title && <AlertTitle>{title}</AlertTitle>}
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  )
}

export function ErrorNotice({ error }: { error: unknown }) {
  return (
    <Alert variant="destructive" role="alert">
      <TriangleAlert aria-hidden="true" />
      <AlertDescription>{errorMessage(error)}</AlertDescription>
    </Alert>
  )
}
