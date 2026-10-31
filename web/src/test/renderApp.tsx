import { QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { vi } from 'vitest'
import { useEffect } from 'react'
import { MemoryRouter, useLocation } from 'react-router'
import { AppRoutes } from '@/AppRoutes'
import { createQueryClient } from '@/queryClient'

function LocationRecorder({ visitedPaths }: { visitedPaths: string[] }) {
  const { pathname } = useLocation()
  useEffect(() => {
    visitedPaths.push(pathname)
  }, [pathname, visitedPaths])
  return null
}

export function renderApp(initialPath: string) {
  const queryClient = createQueryClient()
  const visitedPaths: string[] = []
  const sessionClearedSpy = vi.spyOn(queryClient, 'setQueryData')
  const renderResult = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>
        <LocationRecorder visitedPaths={visitedPaths} />
        <AppRoutes />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  function countSessionExpiredNotifications(): number {
    return sessionClearedSpy.mock.calls.filter(
      ([queryKey, newValue]) => queryKey[0] === 'session' && newValue === false,
    ).length
  }
  return { ...renderResult, queryClient, visitedPaths, countSessionExpiredNotifications }
}
