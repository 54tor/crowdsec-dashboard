import { useTranslation } from 'react-i18next'
import { OVERRIDES_FILE_NAME, type ConfigEditFile } from '@/api/configEditApi'
import { InfoNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'

interface ConfigReadOnlyFileProps {
  file: ConfigEditFile
  onEditOverrides: () => void
}

export function ConfigReadOnlyFile({ file, onEditOverrides }: ConfigReadOnlyFileProps) {
  const { t } = useTranslation()
  return (
    <div className="space-y-3">
      <InfoNotice>{t('configEdit.readOnly', { name: file.name, overrides: OVERRIDES_FILE_NAME })}</InfoNotice>
      <Button type="button" size="sm" variant="outline" onClick={onEditOverrides}>
        {t('configEdit.editOverrides')}
      </Button>
      <pre
        aria-label={t('config.viewer', { name: file.name })}
        tabIndex={0}
        className="max-h-[70vh] overflow-auto rounded-md border bg-secondary p-3 font-mono text-sm whitespace-pre focus-ring"
      >
        {file.content}
      </pre>
    </div>
  )
}
