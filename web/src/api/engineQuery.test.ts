import { describe, expect, it } from 'vitest'
import { withEngine } from '@/api/engineQuery'

describe('withEngine', () => {
  // The API answers 400 to an empty or a repeated engine parameter, so the local
  // engine must be addressed by omitting the parameter entirely.
  it('omitsTheParameterForTheLocalEngineOrNoEngine', () => {
    expect(withEngine('/api/hub/update')).toBe('/api/hub/update')
    expect(withEngine('/api/hub/update', '')).toBe('/api/hub/update')
    expect(withEngine('/api/hub/update', 'local')).toBe('/api/hub/update')
  })

  it('appendsTheEngineAsTheFirstParameter', () => {
    expect(withEngine('/api/bouncers', 'peer')).toBe('/api/bouncers?engine=peer')
  })

  it('appendsTheEngineAfterExistingParameters', () => {
    expect(withEngine('/api/decisions/10?scope=Ip&value=203.0.113.7', 'peer')).toBe('/api/decisions/10?scope=Ip&value=203.0.113.7&engine=peer')
  })

  it('encodesTheEngineName', () => {
    const obtainedUrl = withEngine('/api/hub', 'peer&engine=local')
    expect(obtainedUrl).toBe('/api/hub?engine=peer%26engine%3Dlocal')
    expect(new URL(obtainedUrl, 'http://dashboard.example.com').searchParams.getAll('engine')).toEqual(['peer&engine=local'])
  })
})
