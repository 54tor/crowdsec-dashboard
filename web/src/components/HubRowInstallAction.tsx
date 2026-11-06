import { useTranslation } from 'react-i18next'
import { installHubItem, type HubItemKind } from '@/api/writeApi'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { useHubMutation, type EngineBoundVariables } from '@/hooks/useHubMutation'

export function HubRowInstallAction({ kind, name, engineName }: { kind: HubItemKind; name: string; engineName: string }) {
  const { t } = useTranslation()
  const installation = useHubMutation((installRequest: EngineBoundVariables) => installHubItem(kind, name, installRequest.engineName))
  return (
    <div className="space-y-1">
      <Button
        type="button"
        size="sm"
        variant="outline"
        disabled={installation.isPending}
        aria-label={t('hub.installAria', { name })}
        onClick={() => installation.mutate({ engineName })}
      >
        {installation.isPending ? t('dialog.working') : t('hub.installSubmit')}
      </Button>
      {installation.error && <ErrorNotice error={installation.error} />}
    </div>
  )
}
