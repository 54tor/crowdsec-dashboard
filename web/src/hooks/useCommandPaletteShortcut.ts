import { useEffect, useEffectEvent } from 'react'

const OPEN_DIALOG_SELECTOR = '[role="dialog"], [role="alertdialog"]'

function isPaletteShortcut(keyboardEvent: KeyboardEvent): boolean {
  const hasCommandModifier = keyboardEvent.ctrlKey || keyboardEvent.metaKey
  const hasExtraModifier = keyboardEvent.shiftKey || keyboardEvent.altKey
  return hasCommandModifier && !hasExtraModifier && keyboardEvent.key.toLowerCase() === 'k'
}

export function useCommandPaletteShortcut(onOpen: () => void): void {
  const openPalette = useEffectEvent(onOpen)
  useEffect(() => {
    function handleKeyDown(keyboardEvent: KeyboardEvent) {
      if (!isPaletteShortcut(keyboardEvent)) {
        return
      }
      const isAnotherDialogOpen = document.querySelector(OPEN_DIALOG_SELECTOR) !== null
      if (isAnotherDialogOpen) {
        return
      }
      keyboardEvent.preventDefault()
      openPalette()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])
}
