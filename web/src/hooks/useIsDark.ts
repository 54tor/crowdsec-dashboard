import { useSyncExternalStore } from 'react'

function subscribe(onChange: () => void): () => void {
  const observer = new MutationObserver(onChange)
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
  return () => observer.disconnect()
}

function readIsDark(): boolean {
  return document.documentElement.classList.contains('dark')
}

export function useIsDark(): boolean {
  return useSyncExternalStore(subscribe, readIsDark)
}
