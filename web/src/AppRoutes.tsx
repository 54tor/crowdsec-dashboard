import type { ReactElement } from 'react'
import { Navigate, Route, Routes } from 'react-router'
import { AuthProvider } from '@/auth/AuthProvider'
import { ProtectedRoute } from '@/auth/ProtectedRoute'
import { Layout } from '@/components/Layout'
import { ReloadRequiredProvider } from '@/hooks/ReloadRequiredProvider'
import { Enroll } from '@/pages/Enroll'
import { Login } from '@/pages/Login'
import { Placeholder } from '@/pages/Placeholder'
import { AccountSecurity } from '@/pages/AccountSecurity'
import { Accounts } from '@/pages/Accounts'
import { Alerts } from '@/pages/Alerts'
import { Allowlists } from '@/pages/Allowlists'
import { Bouncers } from '@/pages/Bouncers'
import { Config } from '@/pages/Config'
import { Decisions } from '@/pages/Decisions'
import { Health } from '@/pages/Health'
import { RequireRole } from '@/auth/RequireRole'
import { ExportImport } from '@/pages/ExportImport'
import { Engines } from '@/pages/Engines'
import { Hub } from '@/pages/Hub'
import { Machines } from '@/pages/Machines'
import { Metrics } from '@/pages/Metrics'
import { Sync } from '@/pages/Sync'
import { Tokens } from '@/pages/Tokens'
import { NAV_ITEMS, type NavItem } from '@/routes'

const READ_PAGES: Record<string, ReactElement> = {
  '/alerts': <Alerts />,
  '/decisions': <Decisions />,
  '/allowlists': <Allowlists />,
  '/health': <Health />,
  '/metrics': <Metrics />,
  '/config': <Config />,
  '/bouncers': <Bouncers />,
  '/machines': <Machines />,
  '/hub': <Hub />,
  '/engines': <Engines />,
  '/sync': <Sync />,
  '/tokens': <Tokens />,
  '/accounts': <Accounts />,
  '/export-import': <ExportImport />,
}

function pageFor(navItem: NavItem): ReactElement {
  const page = READ_PAGES[navItem.path] ?? <Placeholder titleKey={navItem.labelKey} />
  return navItem.requiredRole ? <RequireRole role={navItem.requiredRole}>{page}</RequireRole> : page
}

export function AppRoutes() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/enroll" element={<Enroll />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<ReloadRequiredProvider />}>
            <Route element={<Layout />}>
              <Route index element={<Navigate to="/alerts" replace />} />
              {NAV_ITEMS.map((navItem) => (
                <Route key={navItem.path} path={navItem.path} element={pageFor(navItem)} />
              ))}
              <Route path="/account/security" element={<AccountSecurity />} />
            </Route>
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}
