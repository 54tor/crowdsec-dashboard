import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router'
import { useAuth } from '@/auth/useAuth'
import { AppHeader } from '@/components/AppHeader'
import { AppRail } from '@/components/AppRail'
import { ErrorNotice } from '@/components/Notice'

export function Layout() {
  const { t } = useTranslation()
  const { logout } = useAuth()
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
    <div className="min-h-screen bg-background text-foreground md:grid md:grid-cols-[212px_minmax(0,1fr)]">
      <a
        href="#main-content"
        className="sr-only focus-ring focus:not-sr-only focus:absolute focus:z-50 focus:bg-background focus:p-2"
      >
        {t('app.skipToContent')}
      </a>
      <AppRail onLogout={requestLogout} />
      <div className="flex min-w-0 flex-col">
        <AppHeader />
        <main id="main-content" className="mx-auto w-full max-w-[1600px] min-w-0 space-y-4 p-4 md:p-6">
          {logoutError && <ErrorNotice error={logoutError.failure} />}
          <Outlet />
        </main>
      </div>
    </div>
  )
}
