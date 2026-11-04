import { RoleBadge } from '@/components/RoleBadge'

export function AppHeader() {
  return (
    <header className="sticky top-0 z-10 flex min-h-12 items-center justify-end gap-3 border-b bg-background px-4 md:px-6">
      <RoleBadge />
    </header>
  )
}
