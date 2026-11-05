import { describe, expect, it } from 'vitest'
import { alertsSearchPath, decisionsSearchPath, engineAlertsPath } from '@/lib/paletteTargets'

describe('palette targets', () => {
  it('encodesTheTermInTheQuery', () => {
    expect(alertsSearchPath('a&b c')).toBe('/alerts?q=a%26b+c')
    expect(decisionsSearchPath('a&b c')).toBe('/decisions?q=a%26b+c')
  })

  it('encodesTheEngineNameInTheQuery', () => {
    expect(engineAlertsPath('peer/a?b')).toBe('/alerts?engine=peer%2Fa%3Fb')
  })
})
