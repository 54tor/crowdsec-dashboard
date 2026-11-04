import { BrandMark } from '@/components/BrandMark'
import { RailNavGroups } from '@/components/RailNavGroups'
import { ShellControls } from '@/components/ShellControls'

export function AppRail({ onLogout }: { onLogout: () => Promise<void> }) {
  return (
    <aside className="flex flex-col gap-2 border-b bg-card px-3 py-4 md:sticky md:top-0 md:h-screen md:overflow-y-auto md:border-r md:border-b-0">
      <div className="px-2.5 pb-2">
        <BrandMark />
      </div>
      <RailNavGroups />
      <div className="mt-auto pt-4">
        <ShellControls onLogout={onLogout} />
      </div>
    </aside>
  )
}
