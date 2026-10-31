import { LogOut } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, NavLink, Outlet } from 'react-router'
import { useAuth } from '@/auth/useAuth'
import { LanguageSwitch } from '@/components/LanguageSwitch'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { errorMessage } from '@/i18n'
import { NAV_ITEMS } from '@/routes'

export function Layout() {
  const { t } = useTranslation()
  const { accountName, logout } = useAuth()
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
    <div className="flex min-h-screen flex-col bg-background text-foreground md:flex-row">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-background focus:p-2"
      >
        {t('app.skipToContent')}
      </a>
      <aside className="border-b md:w-52 md:shrink-0 md:border-r md:border-b-0">
        <div className="flex flex-wrap items-center justify-between gap-2 p-3">
          <span className="text-sm font-semibold">{t('app.title')}</span>
          <div className="flex items-center gap-2">
            {accountName && (
              <Link to="/account/security" className="max-w-32 truncate text-sm text-muted-foreground underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring">
                {accountName}
              </Link>
            )}
            <LanguageSwitch />
            <LogoutButton onLogout={requestLogout} />
          </div>
        </div>
        <nav aria-label={t('nav.label')} className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:pb-3">
          {NAV_ITEMS.map((navItem) => (
            <NavLink
              key={navItem.path}
              to={navItem.path}
              className={({ isActive }) =>
                cn(
                  'rounded-md px-3 py-2 text-sm whitespace-nowrap outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring',
                  isActive && 'bg-accent font-medium text-accent-foreground',
                )
              }
            >
              {t(navItem.labelKey)}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main id="main-content" className="min-w-0 flex-1 p-4 md:p-6">
        {logoutError && (
          <p role="alert" className="mb-4 text-sm text-destructive">
            {errorMessage(logoutError.failure)}
          </p>
        )}
        <Outlet />
      </main>
    </div>
  )
}

function LogoutButton({ onLogout }: { onLogout: () => Promise<void> }) {
  const { t } = useTranslation()
  return (
    <Button variant="outline" size="sm" onClick={() => void onLogout()}>
      <LogOut aria-hidden="true" />
      <span className="sr-only md:not-sr-only">{t('logout')}</span>
    </Button>
  )
}
