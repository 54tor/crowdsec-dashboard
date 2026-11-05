import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ENGINE_NAMES_QUERY_KEY, listEngineNames } from '@/api/enginesApi'
import { useWritableEngineNames } from '@/hooks/useEngineTarget'
import { ENGINE_NAMES_WITH_SIDECARS } from '@/test/engineTargetHarness'
import { stubFetch, type StubbedResponse } from '@/test/fetchStub'

const ENGINE_NAMES_FAILURE = { status: 500, body: { error: 'internal_error' } }

function renderWithQueryClient(queryClient: QueryClient) {
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  // The second observer re-renders the hook when the query turns to error, so the
  // assertion reads the names computed from that error state.
  return renderHook(() => ({
    writableEngineNames: useWritableEngineNames(),
    engineNamesQuery: useQuery({ queryKey: ENGINE_NAMES_QUERY_KEY, queryFn: listEngineNames, retry: false }),
  }), { wrapper })
}

describe('useWritableEngineNames', () => {
  afterEach(() => vi.unstubAllGlobals())

  // A failed background refresh must not shrink the list to local only: the
  // pages would otherwise silently switch their target engine back to local.
  it('keepsTheLastKnownEngineNamesWhenTheRefreshFails', async () => {
    let engineNamesResponse: StubbedResponse = ENGINE_NAMES_WITH_SIDECARS
    stubFetch({ 'GET /api/engines/names': () => engineNamesResponse })
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const renderedHook = renderWithQueryClient(queryClient)
    await waitFor(() => expect(renderedHook.result.current.writableEngineNames).toEqual(['local', 'peer']))

    engineNamesResponse = ENGINE_NAMES_FAILURE
    await act(() => queryClient.refetchQueries({ queryKey: ENGINE_NAMES_QUERY_KEY }))

    await waitFor(() => expect(renderedHook.result.current.engineNamesQuery.isError).toBe(true))
    expect(renderedHook.result.current.writableEngineNames).toEqual(['local', 'peer'])
  })

  // Without any successful read the list stays local only (fail closed).
  it('offersOnlyTheLocalEngineWhenTheFirstReadFails', async () => {
    stubFetch({ 'GET /api/engines/names': ENGINE_NAMES_FAILURE })
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const renderedHook = renderWithQueryClient(queryClient)

    await waitFor(() => expect(renderedHook.result.current.writableEngineNames).toEqual(['local']))
  })
})
