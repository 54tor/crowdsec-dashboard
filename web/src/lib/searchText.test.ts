import { describe, expect, it } from 'vitest'
import { matchesSearchText, normaliseSearchText } from '@/lib/searchText'

describe('searchText', () => {
  it('ignoresCaseAndAccents', () => {
    expect(matchesSearchText('equipe', ['Équipe'])).toBe(true)
    expect(matchesSearchText('ÉQUIPE', ['equipe'])).toBe(true)
    expect(normaliseSearchText('Éléphant Çà')).toBe('elephant ca')
  })

  it('emptyTermMatchesEverything', () => {
    expect(matchesSearchText('', ['anything'])).toBe(true)
    expect(matchesSearchText('   ', [])).toBe(true)
  })

  // The term is a literal substring: a regular expression would let '.*' match every row.
  it('treatsRegexMetacharactersLiterally', () => {
    expect(matchesSearchText('.*', ['abc'])).toBe(false)
    expect(matchesSearchText('a.c', ['a.c'])).toBe(true)
    expect(matchesSearchText('a.c', ['abc'])).toBe(false)
  })

  // Only combining marks are removed: spacing symbols such as ^ ` ¨ ´ · are part of the term.
  it('keepsSpacingSymbolsThatAreNotCombiningMarks', () => {
    expect(normaliseSearchText('^`¨´·')).toBe('^`¨´·')
    expect(matchesSearchText('^', ['abc'])).toBe(false)
    expect(matchesSearchText('a^b', ['ab'])).toBe(false)
    expect(matchesSearchText('a^b', ['A^B'])).toBe(true)
  })

  it('matchesAnyCandidateAndSkipsMissingTexts', () => {
    expect(matchesSearchText('two', [null, undefined, 'one', 'Two'])).toBe(true)
    expect(matchesSearchText('three', [null, 'one', undefined])).toBe(false)
  })
})
