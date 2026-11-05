import { useState } from 'react'
import { BrandMark } from '@/components/BrandMark'
import { CommandPalette } from '@/components/CommandPalette'
import { CommandPaletteButton } from '@/components/CommandPaletteButton'
import { RoleBadge } from '@/components/RoleBadge'
import { useCommandPaletteShortcut } from '@/hooks/useCommandPaletteShortcut'
import { useIsMobileViewport } from '@/hooks/useMediaQuery'

function focusedElement(): HTMLElement | null {
  const activeElement = document.activeElement
  const isDocumentLevelElement = activeElement === document.body || activeElement === document.documentElement
  if (isDocumentLevelElement || !(activeElement instanceof HTMLElement)) {
    return null
  }
  return activeElement
}

export function AppHeader() {
  const isMobileViewport = useIsMobileViewport()
  const [isPaletteOpen, setIsPaletteOpen] = useState(false)
  const [paletteOpener, setPaletteOpener] = useState<HTMLElement | null>(null)

  function openPalette() {
    setPaletteOpener(focusedElement())
    setIsPaletteOpen(true)
  }

  useCommandPaletteShortcut(openPalette)

  return (
    <header className="sticky top-0 z-10 flex min-h-12 items-center justify-end gap-3 border-b bg-background px-4 md:px-6">
      {isMobileViewport && (
        <div className="mr-auto min-w-0">
          <BrandMark />
        </div>
      )}
      <CommandPaletteButton onOpen={openPalette} />
      <RoleBadge />
      <CommandPalette isOpen={isPaletteOpen} onOpenChange={setIsPaletteOpen} returnFocusElement={paletteOpener} />
    </header>
  )
}
