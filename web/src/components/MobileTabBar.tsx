import { useTranslation } from 'react-i18next'
import { NavLink, useLocation } from 'react-router'
import { useAuth } from '@/auth/useAuth'
import { MOBILE_TAB_CLASS_NAME, MobileTabContent } from '@/components/MobileTab'
import { MoreSheet } from '@/components/MoreSheet'
import { mobileTabItems } from '@/routes'

export function MobileTabBar({ onLogout }: { onLogout: () => Promise<void> }) {
  const { t } = useTranslation()
  const { accountRole } = useAuth()
  const { pathname } = useLocation()
  return (
    <nav
      aria-label={t('shell.mobileNavLabel')}
      className="fixed inset-x-0 bottom-0 z-10 grid grid-cols-5 border-t bg-card px-1 pt-1.5 pb-[env(safe-area-inset-bottom)]"
    >
      {mobileTabItems(accountRole).map((tabItem) => (
        <NavLink key={tabItem.path} to={tabItem.path} className={MOBILE_TAB_CLASS_NAME}>
          <MobileTabContent icon={tabItem.icon} label={t(tabItem.labelKey)} />
        </NavLink>
      ))}
      <MoreSheet key={pathname} onLogout={onLogout} />
    </nav>
  )
}
