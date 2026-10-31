import { describe, expect, it } from 'vitest'
import { validateBanDuration, validateBanReason, validateBanTarget } from '@/lib/banValidation'

describe('ban validation', () => {
  it.each(['203.0.113.7', '203.0.113.0/24', '10.0.0.0/8', '2001:db8::1', '2001:db8::/32'])('acceptsTarget %s', (acceptedTarget) => {
    expect(validateBanTarget(acceptedTarget)).toBeNull()
  })

  it.each([
    ['1.2.3.4/33'],
    ['::ffff:1.2.3.4'],
    ['a'.repeat(44)],
    ['0.0.0.0/0'],
    ['10.0.0.0/7'],
    ['2001:db8::/31'],
    ['fe80::1%eth0'],
    ['203.0.113.7-203.0.113.9'],
    ['not-an-ip'],
  ])('rejectsTarget %s', (rejectedTarget) => {
    expect(validateBanTarget(rejectedTarget)).toBe('invalid_target')
  })

  it.each(['1h', '24h', '7d', '30d', '9999s'])('acceptsDuration %s', (acceptedDuration) => {
    expect(validateBanDuration(acceptedDuration)).toBeNull()
  })

  it.each(['', '1', 'h', '10000s', '1w', '1h '])('rejectsDuration "%s"', (rejectedDuration) => {
    expect(validateBanDuration(rejectedDuration)).toBe('invalid_duration')
  })

  it('acceptsEmptyAndShortReasonButRejectsLongOrControlCharacters', () => {
    expect(validateBanReason('')).toBeNull()
    expect(validateBanReason('x'.repeat(200))).toBeNull()
    expect(validateBanReason('x'.repeat(201))).toBe('invalid_reason')
    expect(validateBanReason('line\nbreak')).toBe('invalid_reason')
  })
})
