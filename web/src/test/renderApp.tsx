import { QueryClientProvider } from '@tanstack/react-query'
import { act, render } from '@testing-library/react'
import { vi } from 'vitest'
import { useEffect } from 'react'
import { MemoryRouter, useLocation, useNavigate, type NavigateFunction } from 'react-router'
import { AppRoutes } from '@/AppRoutes'
import { createQueryClient } from '@/queryClient'

// visitedPaths records path changes only; visitedLocations also records query-string
// changes, so a test can prove that typing in a filter never rewrites the URL.
function LocationRecorder({ visitedPaths, visitedLocations }: { visitedPaths: string[]; visitedLocations: string[] }) {
  const { pathname, search } = useLocation()
  useEffect(() => {
    visitedPaths.push(pathname)
  }, [pathname, visitedPaths])
  useEffect(() => {
    visitedLocations.push(pathname + search)
  }, [pathname, search, visitedLocations])
  return null
}

// Hands the router's navigate function to the test, so a test can follow a link
// to another URL of the same page the way the application itself would.
function NavigatorCapture({ navigatorHolder }: { navigatorHolder: { navigate?: NavigateFunction } }) {
  navigatorHolder.navigate = useNavigate()
  return null
}

export function renderApp(initialPath: string) {
  const queryClient = createQueryClient()
  const visitedPaths: string[] = []
  const visitedLocations: string[] = []
  const navigatorHolder: { navigate?: NavigateFunction } = {}
  const sessionClearedSpy = vi.spyOn(queryClient, 'setQueryData')
  const renderResult = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>
        <LocationRecorder visitedPaths={visitedPaths} visitedLocations={visitedLocations} />
        <NavigatorCapture navigatorHolder={navigatorHolder} />
        <AppRoutes />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  function countSessionExpiredNotifications(): number {
    return sessionClearedSpy.mock.calls.filter(
      ([queryKey, newValue]) => queryKey[0] === 'session' && newValue === false,
    ).length
  }
  async function navigateTo(path: string): Promise<void> {
    await act(async () => {
      await navigatorHolder.navigate?.(path)
    })
  }
  return { ...renderResult, queryClient, visitedPaths, visitedLocations, navigateTo, countSessionExpiredNotifications }
}
