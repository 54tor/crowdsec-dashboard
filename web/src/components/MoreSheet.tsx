import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation } from 'react-router'
import { useAuth } from '@/auth/useAuth'
import { MOBILE_TAB_CLASS_NAME, MobileTabContent } from '@/components/MobileTab'
import { RailNavGroups } from '@/components/RailNavGroups'
import { ShellControls } from '@/components/ShellControls'
import { Dialog, DialogContent, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { moreSheetGroups } from '@/routes'

const BOTTOM_SHEET_CLASS_NAME =
  'top-auto bottom-0 left-0 max-h-[85dvh] w-full max-w-none translate-x-0 translate-y-0 gap-2 overflow-y-auto rounded-b-none pb-[calc(1rem+env(safe-area-inset-bottom))] sm:max-w-none'

export function MoreSheet({ onLogout }: { onLogout: () => Promise<void> }) {
  const { t } = useTranslation()
  const { accountRole } = useAuth()
  const { pathname } = useLocation()
  const [isSheetOpen, setIsSheetOpen] = useState(false)
  const [openedOnPathname, setOpenedOnPathname] = useState(pathname)

  if (pathname !== openedOnPathname) {
    setOpenedOnPathname(pathname)
    setIsSheetOpen(false)
  }

  function closeSheet() {
    setIsSheetOpen(false)
  }

  return (
    <Dialog open={isSheetOpen} onOpenChange={setIsSheetOpen}>
      <DialogTrigger asChild>
        <button type="button" className={MOBILE_TAB_CLASS_NAME}>
          <MobileTabContent icon="more_horiz" label={t('shell.more')} />
        </button>
      </DialogTrigger>
      <DialogContent aria-describedby={undefined} className={BOTTOM_SHEET_CLASS_NAME}>
        <DialogTitle className="px-2.5 pt-1">{t('shell.more')}</DialogTitle>
        <RailNavGroups navItemGroups={moreSheetGroups(accountRole)} onNavigate={closeSheet} />
        <ShellControls onLogout={onLogout} onNavigate={closeSheet} />
      </DialogContent>
    </Dialog>
  )
}
