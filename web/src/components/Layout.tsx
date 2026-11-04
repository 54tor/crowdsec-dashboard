import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router'
import { useAuth } from '@/auth/useAuth'
import { AppHeader } from '@/components/AppHeader'
import { AppRail } from '@/components/AppRail'
import { MobileTabBar } from '@/components/MobileTabBar'
import { ErrorNotice } from '@/components/Notice'
import { useIsMobileViewport } from '@/hooks/useMediaQuery'
import { cn } from '@/lib/utils'

export function Layout() {
  const { t } = useTranslation()
  const { logout } = useAuth()
  const isMobileViewport = useIsMobileViewport()
  const [logoutError, setLogoutError] = useState<{ failure: unknown } | null>(null)

  async function requestLogout() {
    setLogoutError(null)
    try {
      await logout()
    } catch (logoutFailure) {
      setLogoutError({ failure: logoutFailure })
    }
  }

  return (
    <div className={cn('min-h-screen bg-background text-foreground', !isMobileViewport && 'grid grid-cols-[212px_minmax(0,1fr)]')}>
      <a
        href="#main-content"
        className="sr-only focus-ring focus:not-sr-only focus:absolute focus:z-50 focus:bg-background focus:p-2"
      >
        {t('app.skipToContent')}
      </a>
      {!isMobileViewport && <AppRail onLogout={requestLogout} />}
      <div className="flex min-w-0 flex-col">
        <AppHeader />
        <main
          id="main-content"
          tabIndex={-1}
          className={cn('mx-auto w-full max-w-[1600px] min-w-0 space-y-4 outline-none', isMobileViewport ? 'p-4 pb-24' : 'p-6')}
        >
          {logoutError && <ErrorNotice error={logoutError.failure} />}
          <Outlet />
        </main>
      </div>
      {isMobileViewport && <MobileTabBar onLogout={requestLogout} />}
    </div>
  )
}
