import { describe, expect, it } from 'vitest'
import { validateHubName, validateResourceName } from '@/lib/nameValidation'

describe('name validation', () => {
  it.each(['firewall-one', 'a', 'host.example.com', 'bouncer_1'])('acceptsResourceName %s', (acceptedName) => {
    expect(validateResourceName(acceptedName)).toBeNull()
  })

  it.each(['', '-leading', 'with space', 'slash/name', 'x'.repeat(65), 'semi;colon'])('rejectsResourceName "%s"', (rejectedName) => {
    expect(validateResourceName(rejectedName)).toBe('invalid_name')
  })

  it('acceptsOneSlashInHubNamesOnly', () => {
    expect(validateHubName('crowdsecurity/linux')).toBeNull()
    expect(validateHubName('linux')).toBeNull()
    expect(validateHubName('a/b/c')).toBe('invalid_name')
    expect(validateHubName('../etc')).toBe('invalid_name')
  })
})
