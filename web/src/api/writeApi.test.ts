import { afterEach, describe, expect, it, vi } from 'vitest'
import { removeHubItem } from '@/api/writeApi'

describe('hub path building', () => {
  afterEach(() => vi.unstubAllGlobals())

  it.each([['..'], ['.'], ['crowdsecurity/..'], ['../etc'], ['a//b']])('rejectsHostileCollectionName %s before sending', async (hostileName) => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    await expect(removeHubItem('collections', hostileName, hostileName)).rejects.toMatchObject({ code: 'invalid_request' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
