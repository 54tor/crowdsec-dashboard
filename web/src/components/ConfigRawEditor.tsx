import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { ConfigEditFile, ConfigIssue } from '@/api/configEditApi'
import { ConfigDeleteButton } from '@/components/ConfigDeleteButton'
import { ConfigDiscardDialog } from '@/components/ConfigDiscardDialog'
import { ConfigEditFailure } from '@/components/ConfigEditFailure'
import { ConfigIssueList } from '@/components/ConfigIssueList'
import { EngineTargetNote } from '@/components/EngineTargetNote'
import { ErrorNotice, InfoNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { useSaveConfig, useValidateConfig } from '@/hooks/useConfigEdit'

interface Validation {
  validatedContent: string
  issues: ConfigIssue[]
}

interface ConfigRawEditorProps {
  engineName: string
  file: ConfigEditFile
  onDirtyChange: (isDirty: boolean) => void
  onReloadFile: () => void
  onDeleted: () => void
}

export function ConfigRawEditor({ engineName, file, onDirtyChange, onReloadFile, onDeleted }: ConfigRawEditorProps) {
  const { t } = useTranslation()
  const [buffer, setBuffer] = useState(file.content)
  const [validation, setValidation] = useState<Validation | null>(null)
  const [isDiscardOpen, setIsDiscardOpen] = useState(false)
  const validate = useValidateConfig()
  const save = useSaveConfig()
  const isDirty = buffer !== file.content
  const currentValidation = validation?.validatedContent === buffer ? validation : null
  const hasBlockingIssue = currentValidation?.issues.some((issue) => issue.severity === 'error') ?? true
  const canSave = file.writable && currentValidation !== null && !hasBlockingIssue && !save.isPending

  useEffect(() => {
    onDirtyChange(isDirty)
    return () => onDirtyChange(false)
  }, [isDirty, onDirtyChange])

  function runValidation() {
    const contentToValidate = buffer
    validate.mutate(
      { engineName, fileName: file.name, content: contentToValidate },
      { onSuccess: (result) => setValidation({ validatedContent: contentToValidate, issues: result.issues }) },
    )
  }

  function runSave() {
    save.mutate({ engineName, fileName: file.name, content: buffer, expectedDigest: file.digest })
  }

  return (
    <div className="space-y-3">
      <EngineTargetNote engineName={engineName} />
      {!file.exists && <InfoNotice>{t('configEdit.newFile.willCreate', { name: file.name })}</InfoNotice>}
      {!file.writable && <InfoNotice>{t('configEdit.notWritable')}</InfoNotice>}
      <textarea
        aria-label={t('configEdit.editorLabel', { name: file.name })}
        value={buffer}
        readOnly={!file.writable || save.isPending}
        spellCheck={false}
        wrap="off"
        autoCapitalize="off"
        autoCorrect="off"
        onChange={(changeEvent) => setBuffer(changeEvent.target.value)}
        className="block min-h-80 max-h-[70vh] w-full resize-y overflow-auto rounded-md border bg-secondary p-3 font-mono text-sm whitespace-pre focus-ring"
      />
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" size="sm" disabled={validate.isPending || save.isPending} onClick={runValidation}>
          {validate.isPending ? t('dialog.working') : t('configEdit.validate')}
        </Button>
        <Button type="button" size="sm" disabled={!canSave} onClick={runSave}>
          {save.isPending ? t('dialog.working') : t('configEdit.save')}
        </Button>
        {file.exists && (
          <ConfigDeleteButton
            engineName={engineName}
            fileName={file.name}
            digest={file.digest}
            onDeleted={onDeleted}
          />
        )}
      </div>
      {currentValidation === null && <p className="text-sm text-muted-foreground">{t('configEdit.saveNeedsValidation')}</p>}
      <ConfigIssueList issues={currentValidation?.issues ?? null} />
      {validate.error && <ErrorNotice error={validate.error} />}
      {save.error && <ConfigEditFailure failure={save.error} onReloadFile={() => setIsDiscardOpen(true)} />}
      <ConfigDiscardDialog
        isOpen={isDiscardOpen}
        onCancel={() => setIsDiscardOpen(false)}
        onDiscard={() => {
          setIsDiscardOpen(false)
          setBuffer(file.content)
          save.reset()
          onReloadFile()
        }}
      />
    </div>
  )
}
