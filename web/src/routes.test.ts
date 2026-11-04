import { describe, expect, it } from 'vitest'
import { groupNavItems, NAV_ITEMS, visibleNavItems } from '@/routes'

// The order mirrors spec decision 2: monitoring first, then the engines and
// what they run, then accounts and access management.
const APPROVED_PATHS_BY_GROUP = {
  surveillance: ['/alerts', '/decisions', '/health', '/metrics'],
  infrastructure: ['/engines', '/sync', '/hub', '/allowlists', '/config'],
  administration: ['/tokens', '/accounts', '/export-import', '/account/security', '/bouncers', '/machines'],
}

const ADMIN_ONLY_PATHS = ['/engines', '/config', '/accounts', '/export-import']

describe('navigation grouping', () => {
  it('groupsFollowTheApprovedOrder', () => {
    const navigationGroups = groupNavItems(visibleNavItems('admin'))

    const obtainedGroupNames = navigationGroups.map((navigationGroup) => navigationGroup.group)
    expect(obtainedGroupNames).toEqual(['surveillance', 'infrastructure', 'administration'])
    for (const navigationGroup of navigationGroups) {
      const obtainedPaths = navigationGroup.items.map((navItem) => navItem.path)
      expect(obtainedPaths).toEqual(APPROVED_PATHS_BY_GROUP[navigationGroup.group])
    }
  })

  it('readOnlyRailHidesAdminEntries', () => {
    const readOnlyPaths = visibleNavItems('read_only').map((navItem) => navItem.path)

    for (const adminOnlyPath of ADMIN_ONLY_PATHS) {
      expect(readOnlyPaths).not.toContain(adminOnlyPath)
    }
    expect(readOnlyPaths).toContain('/account/security')
  })

  it('groupWithoutVisibleEntryIsOmitted', () => {
    const alertsItem = NAV_ITEMS.find((navItem) => navItem.path === '/alerts')!

    const navigationGroups = groupNavItems([alertsItem])

    expect(navigationGroups).toHaveLength(1)
    expect(navigationGroups[0].group).toBe('surveillance')
  })
})
