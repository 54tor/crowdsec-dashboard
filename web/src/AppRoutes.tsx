import { Navigate, Route, Routes } from 'react-router'
import { AuthProvider } from '@/auth/AuthProvider'
import { ProtectedRoute } from '@/auth/ProtectedRoute'
import { Layout } from '@/components/Layout'
import { Login } from '@/pages/Login'
import { Placeholder } from '@/pages/Placeholder'
import { NAV_ITEMS } from '@/routes'

export function AppRoutes() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route index element={<Navigate to="/alerts" replace />} />
            {NAV_ITEMS.map((navItem) => (
              <Route key={navItem.path} path={navItem.path} element={<Placeholder titleKey={navItem.labelKey} />} />
            ))}
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}
