import type { AccountRole } from '@/auth/AuthContext'
import type { IconName } from '@/components/iconSources'

export type NavGroup = 'surveillance' | 'infrastructure' | 'administration'

export interface NavItem {
  path: string
  labelKey: string
  icon: IconName
  group: NavGroup
  requiredRole?: AccountRole
}

export interface NavItemGroup {
  group: NavGroup
  items: readonly NavItem[]
}

export const NAV_GROUP_ORDER: readonly NavGroup[] = ['surveillance', 'infrastructure', 'administration']

export const NAV_ITEMS: readonly NavItem[] = [
  { path: '/alerts', labelKey: 'nav.alerts', icon: 'warning', group: 'surveillance' },
  { path: '/decisions', labelKey: 'nav.decisions', icon: 'gavel', group: 'surveillance' },
  { path: '/health', labelKey: 'nav.health', icon: 'favorite', group: 'surveillance' },
  { path: '/metrics', labelKey: 'nav.metrics', icon: 'bar_chart', group: 'surveillance' },
  { path: '/engines', labelKey: 'nav.engines', icon: 'lan', group: 'infrastructure', requiredRole: 'admin' },
  { path: '/sync', labelKey: 'nav.sync', icon: 'sync', group: 'infrastructure' },
  { path: '/hub', labelKey: 'nav.hub', icon: 'apps', group: 'infrastructure' },
  { path: '/allowlists', labelKey: 'nav.allowlists', icon: 'checklist', group: 'infrastructure' },
  { path: '/config', labelKey: 'nav.config', icon: 'tune', group: 'infrastructure', requiredRole: 'admin' },
  { path: '/tokens', labelKey: 'nav.tokens', icon: 'key', group: 'administration' },
  { path: '/accounts', labelKey: 'nav.accounts', icon: 'group', group: 'administration', requiredRole: 'admin' },
  { path: '/export-import', labelKey: 'nav.exportImport', icon: 'swap_horiz', group: 'administration', requiredRole: 'admin' },
  { path: '/account/security', labelKey: 'nav.accountSecurity', icon: 'lock', group: 'administration' },
  { path: '/bouncers', labelKey: 'nav.bouncers', icon: 'shield', group: 'administration' },
  { path: '/machines', labelKey: 'nav.machines', icon: 'dns', group: 'administration' },
]

export function visibleNavItems(accountRole: AccountRole | null): readonly NavItem[] {
  return NAV_ITEMS.filter((navItem) => navItem.requiredRole === undefined || navItem.requiredRole === accountRole)
}

export function groupNavItems(navItems: readonly NavItem[]): NavItemGroup[] {
  const navItemGroups = NAV_GROUP_ORDER.map((group) => ({
    group,
    items: navItems.filter((navItem) => navItem.group === group),
  }))
  return navItemGroups.filter((navItemGroup) => navItemGroup.items.length > 0)
}

export const MOBILE_TAB_PATHS: readonly string[] = ['/alerts', '/decisions', '/sync', '/engines']

const MOBILE_TAB_FALLBACK_PATHS: readonly string[] = ['/health']

function isNavItem(candidate: NavItem | undefined): candidate is NavItem {
  return candidate !== undefined
}

export function mobileTabItems(accountRole: AccountRole | null): readonly NavItem[] {
  const visibleItems = visibleNavItems(accountRole)
  const candidatePaths = [...MOBILE_TAB_PATHS, ...MOBILE_TAB_FALLBACK_PATHS]
  const candidateItems = candidatePaths
    .map((candidatePath) => visibleItems.find((navItem) => navItem.path === candidatePath))
    .filter(isNavItem)
  return candidateItems.slice(0, MOBILE_TAB_PATHS.length)
}

export function moreSheetGroups(accountRole: AccountRole | null): NavItemGroup[] {
  const tabPaths = new Set(mobileTabItems(accountRole).map((tabItem) => tabItem.path))
  const remainingItems = visibleNavItems(accountRole).filter((navItem) => !tabPaths.has(navItem.path))
  return groupNavItems(remainingItems)
}
