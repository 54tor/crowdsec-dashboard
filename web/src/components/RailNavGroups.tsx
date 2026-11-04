import { useId } from 'react'
import { useTranslation } from 'react-i18next'
import { NavLink } from 'react-router'
import { Icon } from '@/components/Icon'
import { cn } from '@/lib/utils'
import type { NavItemGroup } from '@/routes'

function railLinkClassName({ isActive }: { isActive: boolean }): string {
  return cn(
    'relative flex min-h-10 items-center max-md:min-h-11 gap-3 rounded-md px-2.5 text-sm text-muted-foreground focus-ring hover:bg-secondary hover:text-foreground',
    isActive &&
      'bg-secondary font-medium text-foreground before:absolute before:inset-y-1.5 before:-left-3 before:w-[3px] before:rounded-r before:bg-primary',
  )
}

function RailNavGroup({ navItemGroup, onNavigate }: { navItemGroup: NavItemGroup; onNavigate?: () => void }) {
  const { t } = useTranslation()
  const headingId = useId()
  return (
    <div>
      <h2 id={headingId} className="px-2.5 pt-3.5 pb-1.5 font-condensed text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
        {t(`shell.groups.${navItemGroup.group}`)}
      </h2>
      <ul aria-labelledby={headingId} className="space-y-0.5">
        {navItemGroup.items.map((navItem) => (
          <li key={navItem.path}>
            <NavLink to={navItem.path} className={railLinkClassName} onClick={onNavigate}>
              <Icon name={navItem.icon} className="size-5" />
              {t(navItem.labelKey)}
            </NavLink>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function RailNavGroups({
  navItemGroups,
  onNavigate,
}: {
  navItemGroups: readonly NavItemGroup[]
  onNavigate?: () => void
}) {
  const { t } = useTranslation()
  return (
    <nav aria-label={t('nav.label')}>
      {navItemGroups.map((navItemGroup) => (
        <RailNavGroup key={navItemGroup.group} navItemGroup={navItemGroup} onNavigate={onNavigate} />
      ))}
    </nav>
  )
}
