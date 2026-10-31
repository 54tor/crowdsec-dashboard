import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { installCollection } from '@/api/writeApi'
import { FormField } from '@/components/FormField'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { useHubMutation } from '@/hooks/useHubMutation'
import { validateHubName } from '@/lib/nameValidation'

function InstallForm({ onDone, onClose }: { onDone: () => void; onClose: () => void }) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const installation = useHubMutation(installCollection, onDone)
  const nameError = name === '' ? null : validateHubName(name)
  const isValid = name !== '' && !nameError

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (isValid && !installation.isPending) {
      installation.mutate(name)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <DialogHeader>
        <DialogTitle>{t('hub.installTitle')}</DialogTitle>
        <DialogDescription>{t('hub.installDescription')}</DialogDescription>
      </DialogHeader>
      <FormField
        id="install-collection-name"
        label={t('hub.installName')}
        value={name}
        onChange={(changeEvent) => setName(changeEvent.target.value)}
        error={nameError && t(`errors.${nameError}`)}
      />
      {installation.error && <ErrorNotice error={installation.error} />}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          {t('dialog.cancel')}
        </Button>
        <Button type="submit" disabled={!isValid || installation.isPending}>
          {installation.isPending ? t('dialog.working') : t('hub.installSubmit')}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function InstallCollectionDialog() {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)
  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button type="button">{t('hub.install')}</Button>
      </DialogTrigger>
      <DialogContent showCloseButton={false}>
        <InstallForm onDone={() => setIsOpen(false)} onClose={() => setIsOpen(false)} />
      </DialogContent>
    </Dialog>
  )
}
