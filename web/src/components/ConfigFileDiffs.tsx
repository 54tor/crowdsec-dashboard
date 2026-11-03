import { useTranslation } from 'react-i18next'
import type { FileAction } from '@/api/bundleApi'
import { UntrustedText } from '@/components/UntrustedText'

const MAX_DIFF_CHARACTERS = 20_000

export function ConfigFileDiffs({ files }: { files: readonly FileAction[] }) {
  const { t } = useTranslation()
  if (files.length === 0) {
    return null
  }
  return (
    <div className="space-y-2">
      <h4 className="text-sm font-medium">{t('bundle.configFilesTitle')}</h4>
      {files.map((fileAction) => (
        <details key={fileAction.name} className="rounded border p-2 text-sm">
          <summary>
            <UntrustedText value={fileAction.name} /> — {t(`bundle.fileChange.${fileAction.change}`, { defaultValue: t('bundle.unknownCode', { code: fileAction.change }) })}
          </summary>
          {fileAction.diff !== '' && <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs">{fileAction.diff.slice(0, MAX_DIFF_CHARACTERS)}</pre>}
          {(fileAction.diff_truncated || fileAction.diff.length > MAX_DIFF_CHARACTERS) && <p className="text-xs text-muted-foreground">{t('bundle.diffTruncated')}</p>}
        </details>
      ))}
    </div>
  )
}
