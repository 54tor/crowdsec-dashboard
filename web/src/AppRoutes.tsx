import type { ReactElement } from 'react'
import { Navigate, Route, Routes } from 'react-router'
import { AuthProvider } from '@/auth/AuthProvider'
import { ProtectedRoute } from '@/auth/ProtectedRoute'
import { Layout } from '@/components/Layout'
import { ReloadRequiredProvider } from '@/hooks/ReloadRequiredProvider'
import { Login } from '@/pages/Login'
import { Placeholder } from '@/pages/Placeholder'
import { Alerts } from '@/pages/Alerts'
import { Bouncers } from '@/pages/Bouncers'
import { Config } from '@/pages/Config'
import { Decisions } from '@/pages/Decisions'
import { Health } from '@/pages/Health'
import { Hub } from '@/pages/Hub'
import { Machines } from '@/pages/Machines'
import { Metrics } from '@/pages/Metrics'
import { NAV_ITEMS } from '@/routes'

const READ_PAGES: Record<string, ReactElement> = {
  '/alerts': <Alerts />,
  '/decisions': <Decisions />,
  '/health': <Health />,
  '/metrics': <Metrics />,
  '/config': <Config />,
  '/bouncers': <Bouncers />,
  '/machines': <Machines />,
  '/hub': <Hub />,
}

function pageFor(path: string, labelKey: string): ReactElement {
  return READ_PAGES[path] ?? <Placeholder titleKey={labelKey} />
}

export function AppRoutes() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<ReloadRequiredProvider />}>
            <Route element={<Layout />}>
              <Route index element={<Navigate to="/alerts" replace />} />
              {NAV_ITEMS.map((navItem) => (
                <Route key={navItem.path} path={navItem.path} element={pageFor(navItem.path, navItem.labelKey)} />
              ))}
            </Route>
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}
