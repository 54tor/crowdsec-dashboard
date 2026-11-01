import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { testEngine } from '@/api/enginesApi'
import { ErrorNotice, InfoNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'

export function EngineTestButton({ engineName }: { engineName: string }) {
  const { t } = useTranslation()
  const connectionTest = useMutation({ mutationFn: () => testEngine(engineName) })
  return (
    <div className="space-y-1">
      <Button type="button" size="sm" variant="outline" aria-label={t('engines.testAria', { name: engineName })} disabled={connectionTest.isPending} onClick={() => connectionTest.mutate()}>
        {connectionTest.isPending ? t('engines.testing') : t('engines.test')}
      </Button>
      {connectionTest.isSuccess && <InfoNotice>{t('engines.testOk')}</InfoNotice>}
      {connectionTest.isError && <ErrorNotice error={connectionTest.error} />}
    </div>
  )
}
