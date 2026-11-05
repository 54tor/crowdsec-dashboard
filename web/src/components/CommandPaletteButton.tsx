import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import { Button } from '@/components/ui/button'

export function CommandPaletteButton({ onOpen }: { onOpen: () => void }) {
  const { t } = useTranslation()
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={onOpen}
      aria-keyshortcuts="Control+K Meta+K"
      className="max-md:size-11 max-md:px-0"
    >
      <Icon name="search" className="size-4" />
      <span className="max-md:sr-only">{t('palette.open')}</span>
    </Button>
  )
}
