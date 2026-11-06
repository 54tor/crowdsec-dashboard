import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { FormField } from '@/components/FormField'
import { Button } from '@/components/ui/button'

const NEW_FILE_NAME_PATTERN =
  /^(acquis\.d\/[A-Za-z0-9][A-Za-z0-9._-]*\.yaml|(parsers|postoverflows)\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]*whitelist[A-Za-z0-9._-]*\.yaml|config\.yaml\.local)$/i

const isAcceptableNewFileName = (fileName: string) => NEW_FILE_NAME_PATTERN.test(fileName) && !fileName.includes('..')

interface ConfigNewFileFormProps {
  onCreate: (fileName: string) => void
}

export function ConfigNewFileForm({ onCreate }: ConfigNewFileFormProps) {
  const { t } = useTranslation()
  const [typedName, setTypedName] = useState('')
  const [hasSubmitted, setHasSubmitted] = useState(false)
  const isAcceptable = isAcceptableNewFileName(typedName)

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    setHasSubmitted(true)
    if (isAcceptable) {
      onCreate(typedName)
      setTypedName('')
      setHasSubmitted(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-2">
      <FormField
        id="config-new-file"
        label={t('configEdit.newFile.label')}
        hint={t('configEdit.newFile.hint')}
        error={hasSubmitted && !isAcceptable ? t('configEdit.newFile.invalid') : null}
        value={typedName}
        onChange={(changeEvent) => setTypedName(changeEvent.target.value)}
      />
      <Button type="submit" size="sm" variant="outline">
        {t('configEdit.newFile.create')}
      </Button>
    </form>
  )
}
