import { useQueryClient } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { HUB_QUERY_KEY } from '@/hooks/useReadResources'
import { errorMessage } from '@/i18n'
import { isTimeoutError } from '@/lib/apiErrors'

export function InfoNotice({ children }: { children: ReactNode }) {
  return (
    <Alert variant="info" role="status">
      <Icon name="info" className="size-4" />
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  )
}

export function WarningNotice({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <Alert variant="warning" role="status">
      <Icon name="warning" className="size-4" />
      {title && <AlertTitle>{title}</AlertTitle>}
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  )
}

export function ErrorNotice({ error, message }: { error: unknown; message?: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  return (
    <Alert variant="critical" role="alert">
      <Icon name="warning" className="size-4" />
      <AlertDescription>
        {message ?? errorMessage(error)}
        {isTimeoutError(error) && (
          <Button type="button" variant="outline" size="sm" className="mt-2" onClick={() => void queryClient.invalidateQueries({ queryKey: HUB_QUERY_KEY })}>
            {t('errors.refresh')}
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}
