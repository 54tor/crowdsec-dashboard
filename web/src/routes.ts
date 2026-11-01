import type { AccountRole } from '@/auth/AuthContext'

export interface NavItem {
  path: string
  labelKey: string
  requiredRole?: AccountRole
}

export const NAV_ITEMS: readonly NavItem[] = [
  { path: '/alerts', labelKey: 'nav.alerts' },
  { path: '/decisions', labelKey: 'nav.decisions' },
  { path: '/health', labelKey: 'nav.health' },
  { path: '/metrics', labelKey: 'nav.metrics' },
  { path: '/config', labelKey: 'nav.config' },
  { path: '/bouncers', labelKey: 'nav.bouncers' },
  { path: '/machines', labelKey: 'nav.machines' },
  { path: '/hub', labelKey: 'nav.hub' },
  { path: '/engines', labelKey: 'nav.engines', requiredRole: 'admin' },
]

export function visibleNavItems(accountRole: AccountRole | null): readonly NavItem[] {
  return NAV_ITEMS.filter((navItem) => navItem.requiredRole === undefined || navItem.requiredRole === accountRole)
}
