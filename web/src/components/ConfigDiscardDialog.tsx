import { useTranslation } from 'react-i18next'
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog'

interface ConfigDiscardDialogProps {
  isOpen: boolean
  onCancel: () => void
  onDiscard: () => void
}

export function ConfigDiscardDialog({ isOpen, onCancel, onDiscard }: ConfigDiscardDialogProps) {
  const { t } = useTranslation()
  return (
    <ConfirmActionDialog
      open={isOpen}
      onOpenChange={(isDialogOpen) => !isDialogOpen && onCancel()}
      trigger={<span hidden />}
      title={t('configEdit.discard.title')}
      description={t('configEdit.discard.body')}
      submitLabel={t('configEdit.discard.confirm')}
      request={() => Promise.resolve()}
      onDone={onDiscard}
      onFailed={onCancel}
    />
  )
}
