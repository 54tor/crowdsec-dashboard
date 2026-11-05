import { describe, expect, it } from 'vitest'
import { isSearchTermTooShort, validateFilters } from '@/lib/filterValidation'

describe('filter validation', () => {
  it.each(['203.0.113.7', '203.0.113.0/24', '2001:db8::1', '2001:db8::/32', '::1', ''])(
    'acceptsIp %s',
    (ipCandidate) => {
      expect(validateFilters({ scenario: '', ip: ipCandidate, since: '' })).toEqual({})
    },
  )

  it.each(['1.2.3.4/33', '2001:db8::/129', '1.2.3', '300.1.1.1', 'abc', '1.2.3.4/', '1.2.3.4/-1', '1.2.3.4 ', '0x7f.1'])(
    'rejectsIp %s',
    (ipCandidate) => {
      expect(validateFilters({ scenario: '', ip: ipCandidate, since: '' })).toEqual({ ip: 'ipInvalid' })
    },
  )

  it('rejectsMalformedScenarioAndSince', () => {
    expect(validateFilters({ scenario: '<img>', ip: '', since: '24 hours' })).toEqual({
      scenario: 'scenarioInvalid',
      since: 'sinceInvalid',
    })
    expect(validateFilters({ scenario: 'a'.repeat(300), ip: '', since: '' })).toEqual({ scenario: 'scenarioInvalid' })
  })

  it('acceptsCrowdsecScenarioAndDuration', () => {
    expect(validateFilters({ scenario: 'crowdsecurity/ssh-bf', ip: '', since: '24h' })).toEqual({})
  })

  it.each(['ab', ' ab '])('flagsSearchTermsShorterThanThreeCharacters %j', (tooShortTerm) => {
    expect(isSearchTermTooShort(tooShortTerm)).toBe(true)
    expect(validateFilters({ scenario: '', ip: '', since: '', q: tooShortTerm })).toEqual({ q: 'searchTooShort' })
  })

  it.each(['', '   ', 'abc', ' 198.51 '])('acceptsBlankOrLongEnoughSearchTerms %j', (acceptedTerm) => {
    expect(isSearchTermTooShort(acceptedTerm)).toBe(false)
    expect(validateFilters({ scenario: '', ip: '', since: '', q: acceptedTerm })).toEqual({})
  })

  it('flagsSearchTermsLongerThanSixtyFourCharacters', () => {
    expect(validateFilters({ scenario: '', ip: '', since: '', q: 'a'.repeat(65) })).toEqual({ q: 'searchTooLong' })
    expect(validateFilters({ scenario: '', ip: '', since: '', q: 'a'.repeat(64) })).toEqual({})
  })

  // Mirrors the backend's unicode.IsControl check (category Cc, C1 controls included).
  // A tab inside the term is a control character; surrounding whitespace is trimmed first.
  it.each(['ssh\tbf', 'abc\u0000', '\u007fabc', 'abc\u0085def', 'a\u001bbc'])('flagsSearchTermsContainingAControlCharacter %j', (controlCharacterTerm) => {
    expect(validateFilters({ scenario: '', ip: '', since: '', q: controlCharacterTerm })).toEqual({ q: 'searchInvalid' })
  })
})
