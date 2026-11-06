import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { isProtectedFromDeletion } from '@/api/configEditApi'
import { ConfirmDeleteDialog } from '@/components/ConfirmDeleteDialog'
import { Button } from '@/components/ui/button'
import { useDeleteConfig } from '@/hooks/useConfigEdit'

interface ConfigDeleteButtonProps {
  engineName: string
  fileName: string
  digest: string
  onDeleted: () => void
}

export function ConfigDeleteButton({ engineName, fileName, digest, onDeleted }: ConfigDeleteButtonProps) {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)
  const deletion = useDeleteConfig()
  const isProtected = isProtectedFromDeletion(fileName)
  return (
    <ConfirmDeleteDialog
      open={isOpen}
      onOpen={() => setIsOpen(true)}
      onClose={() => setIsOpen(false)}
      trigger={
        <Button type="button" variant="destructive" size="sm" disabled={isProtected}>
          {t('configEdit.delete.open')}
        </Button>
      }
      title={t('configEdit.delete.title')}
      description={t('configEdit.delete.description', { name: fileName })}
      target={fileName}
      engineName={engineName}
      submitLabel={t('configEdit.delete.submit')}
      request={(confirm) => deletion.mutateAsync({ engineName, fileName, expectedDigest: digest, confirm })}
      onDeleted={() => {
        setIsOpen(false)
        onDeleted()
      }}
    />
  )
}
