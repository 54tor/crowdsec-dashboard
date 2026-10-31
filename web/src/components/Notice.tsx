import { useQueryClient } from '@tanstack/react-query'
import { Info, TriangleAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
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

function isTimeout(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'cscli_timeout'
}

export function ErrorNotice({ error }: { error: unknown }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  return (
    <Alert variant="destructive" role="alert">
      <TriangleAlert aria-hidden="true" />
      <AlertDescription>
        {errorMessage(error)}
        {isTimeout(error) && (
          <Button type="button" variant="outline" size="sm" className="mt-2" onClick={() => void queryClient.invalidateQueries()}>
            {t('errors.refresh')}
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}
