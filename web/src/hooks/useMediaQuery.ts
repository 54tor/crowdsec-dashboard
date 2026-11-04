import { useCallback, useSyncExternalStore } from 'react'

export const MOBILE_VIEWPORT_QUERY = '(max-width: 767px)'

export function useMediaQuery(query: string): boolean {
  const subscribeToQuery = useCallback(
    (onQueryChange: () => void) => {
      const mediaQueryList = window.matchMedia(query)
      mediaQueryList.addEventListener('change', onQueryChange)
      return () => mediaQueryList.removeEventListener('change', onQueryChange)
    },
    [query],
  )
  const readQueryMatches = useCallback(() => window.matchMedia(query).matches, [query])
  return useSyncExternalStore(subscribeToQuery, readQueryMatches)
}

export function useIsMobileViewport(): boolean {
  return useMediaQuery(MOBILE_VIEWPORT_QUERY)
}
