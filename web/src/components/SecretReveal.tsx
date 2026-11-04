import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import { Button } from '@/components/ui/button'

type CopyOutcome = 'idle' | 'copied' | 'failed'

export function SecretReveal({ label, secret }: { label: string; secret: string }) {
  const { t } = useTranslation()
  const [copyOutcome, setCopyOutcome] = useState<CopyOutcome>('idle')

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(secret)
      setCopyOutcome('copied')
    } catch {
      setCopyOutcome('failed')
    }
  }

  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">{label}</p>
      <code className="block rounded-md border bg-secondary p-2 font-mono text-sm text-foreground break-all select-all">{secret}</code>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" variant="outline" size="sm" onClick={copySecret}>
          <Icon name="content_copy" className="size-3.5" />
          {t('secret.copy')}
        </Button>
        <p aria-live="polite" className="text-sm text-muted-foreground">
          {copyOutcome === 'copied' && t('secret.copied')}
          {copyOutcome === 'failed' && t('secret.copyFailed')}
        </p>
      </div>
    </div>
  )
}
