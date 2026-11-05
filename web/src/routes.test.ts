import { describe, expect, it } from 'vitest'
import { groupNavItems, moreSheetGroups, NAV_ITEMS, visibleNavItems } from '@/routes'

// The order mirrors spec decision 2: monitoring first, then the engines and
// what they run, then accounts and access management.
const APPROVED_PATHS_BY_GROUP = {
  surveillance: ['/alerts', '/decisions', '/health', '/metrics'],
  infrastructure: ['/engines', '/sync', '/hub', '/allowlists', '/config'],
  administration: ['/tokens', '/accounts', '/audit', '/export-import', '/account/security', '/bouncers', '/machines'],
}

const ADMIN_ONLY_PATHS = ['/engines', '/config', '/accounts', '/audit', '/export-import']
const AUDIT_PATH = '/audit'

function moreSheetPaths(accountRole: 'admin' | 'read_only'): string[] {
  return moreSheetGroups(accountRole).flatMap((navigationGroup) => navigationGroup.items.map((navItem) => navItem.path))
}

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

  it('readOnlyNavHasNoAuditEntry', () => {
    const readOnlyPaths = visibleNavItems('read_only').map((navItem) => navItem.path)

    expect(readOnlyPaths).not.toContain(AUDIT_PATH)
    expect(moreSheetPaths('read_only')).not.toContain(AUDIT_PATH)
  })

  it('adminNavListsAuditInAdministration', () => {
    const administrationGroup = groupNavItems(visibleNavItems('admin')).find((navigationGroup) => navigationGroup.group === 'administration')!

    const administrationPaths = administrationGroup.items.map((navItem) => navItem.path)
    expect(administrationPaths).toContain(AUDIT_PATH)
    const adminMoreSheetGroup = moreSheetGroups('admin').find((navigationGroup) => navigationGroup.group === 'administration')!
    expect(adminMoreSheetGroup.items.map((navItem) => navItem.path)).toContain(AUDIT_PATH)
  })
})
