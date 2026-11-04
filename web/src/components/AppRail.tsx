import { useAuth } from '@/auth/useAuth'
import { BrandMark } from '@/components/BrandMark'
import { RailNavGroups } from '@/components/RailNavGroups'
import { ShellControls } from '@/components/ShellControls'
import { groupNavItems, visibleNavItems } from '@/routes'

export function AppRail({ onLogout }: { onLogout: () => Promise<void> }) {
  const { accountRole } = useAuth()
  return (
    <div data-slot="app-rail" className="sticky top-0 flex h-screen flex-col gap-2 overflow-hidden border-r bg-card px-3 py-4">
      <div className="shrink-0 px-2.5 pb-2">
        <BrandMark />
      </div>
      <RailNavGroups
        navItemGroups={groupNavItems(visibleNavItems(accountRole))}
        className="-mx-3 min-h-0 flex-1 overflow-y-auto px-3 [scrollbar-width:thin]"
      />
      <div data-slot="app-rail-footer" className="shrink-0 border-t pt-3">
        <ShellControls onLogout={onLogout} />
      </div>
    </div>
  )
}
