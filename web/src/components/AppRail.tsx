import { useAuth } from '@/auth/useAuth'
import { BrandMark } from '@/components/BrandMark'
import { RailNavGroups } from '@/components/RailNavGroups'
import { ShellControls } from '@/components/ShellControls'
import { groupNavItems, visibleNavItems } from '@/routes'

export function AppRail({ onLogout }: { onLogout: () => Promise<void> }) {
  const { accountRole } = useAuth()
  return (
    <aside className="sticky top-0 flex h-screen flex-col gap-2 overflow-y-auto border-r bg-card px-3 py-4">
      <div className="px-2.5 pb-2">
        <BrandMark />
      </div>
      <RailNavGroups navItemGroups={groupNavItems(visibleNavItems(accountRole))} />
      <div className="mt-auto pt-4">
        <ShellControls onLogout={onLogout} />
      </div>
    </aside>
  )
}
