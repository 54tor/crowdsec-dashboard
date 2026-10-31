import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiFetch, resetUnauthenticatedGuard, setUnauthenticatedHandler } from './client'
import { stubFetch } from '@/test/fetchStub'

describe('apiFetch', () => {
  const unauthenticatedHandler = vi.fn()

  beforeEach(() => {
    unauthenticatedHandler.mockClear()
    resetUnauthenticatedGuard()
    setUnauthenticatedHandler(unauthenticatedHandler)
  })

  afterEach(() => {
    setUnauthenticatedHandler(null)
    vi.unstubAllGlobals()
  })

  it('redirectsToLoginOnceOnUnauthenticated', async () => {
    stubFetch({ 'GET /api/alerts': { status: 401, body: { error: 'unauthenticated' } } })
    for (let attemptNumber = 0; attemptNumber < 3; attemptNumber += 1) {
      await expect(apiFetch('/api/alerts')).rejects.toMatchObject({ code: 'unauthenticated', status: 401 })
    }
    expect(unauthenticatedHandler).toHaveBeenCalledTimes(1)
  })

  it('doesNotRedirectOnInvalidCredentials', async () => {
    stubFetch({ 'POST /api/auth/login': { status: 401, body: { error: 'invalid_credentials' } } })
    await expect(apiFetch('/api/auth/login', { method: 'POST' })).rejects.toBeInstanceOf(ApiError)
    expect(unauthenticatedHandler).not.toHaveBeenCalled()
  })

  it('redirectsAgainAfterGuardReset', async () => {
    stubFetch({ 'GET /api/alerts': { status: 401, body: { error: 'unauthenticated' } } })
    await expect(apiFetch('/api/alerts')).rejects.toBeInstanceOf(ApiError)
    resetUnauthenticatedGuard()
    await expect(apiFetch('/api/alerts')).rejects.toBeInstanceOf(ApiError)
    expect(unauthenticatedHandler).toHaveBeenCalledTimes(2)
  })

  it('mapsNetworkFailureAndNonJsonErrorToStableCodes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))
    await expect(apiFetch('/api/x')).rejects.toMatchObject({ code: 'network', status: 0 })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>', { status: 500 })))
    await expect(apiFetch('/api/x')).rejects.toMatchObject({ code: 'unknown', status: 500 })
  })

  it('returnsParsedJsonOnSuccess', async () => {
    stubFetch({ 'GET /api/auth/me': { status: 200, body: { status: 'ok' } } })
    await expect(apiFetch('/api/auth/me')).resolves.toEqual({ status: 'ok' })
  })
})
