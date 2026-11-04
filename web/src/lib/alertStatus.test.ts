import { describe, expect, it } from 'vitest'
import { alertStatusOf, type AlertStatus } from '@/lib/alertStatus'
import { makeAlert, makeDecision } from '@/test/fixtures'

describe('alert status', () => {
  // Simulation wins over decisions: a simulated alert never bans anyone,
  // even when the engine attached a (simulated) decision to it.
  it.each<{ situation: string; simulated: boolean; decisionCount: number; expectedStatus: AlertStatus }>([
    { situation: 'simulated alert with a decision', simulated: true, decisionCount: 1, expectedStatus: 'simulated' },
    { situation: 'real alert with a decision', simulated: false, decisionCount: 1, expectedStatus: 'activeBan' },
    { situation: 'real alert without decision', simulated: false, decisionCount: 0, expectedStatus: 'report' },
  ])('$situation is $expectedStatus', ({ simulated, decisionCount, expectedStatus }) => {
    const alertRow = makeAlert({ simulated, decisions: Array.from({ length: decisionCount }, () => makeDecision()) })

    expect(alertStatusOf(alertRow)).toBe(expectedStatus)
  })
})
