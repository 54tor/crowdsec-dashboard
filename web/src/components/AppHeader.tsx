import { BrandMark } from '@/components/BrandMark'
import { RoleBadge } from '@/components/RoleBadge'
import { useIsMobileViewport } from '@/hooks/useMediaQuery'

export function AppHeader() {
  const isMobileViewport = useIsMobileViewport()
  return (
    <header className="sticky top-0 z-10 flex min-h-12 items-center justify-end gap-3 border-b bg-background px-4 md:px-6">
      {isMobileViewport && (
        <div className="mr-auto min-w-0">
          <BrandMark />
        </div>
      )}
      <RoleBadge />
    </header>
  )
}
