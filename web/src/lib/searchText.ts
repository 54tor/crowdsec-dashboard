const COMBINING_MARK_PATTERN = /\p{M}/gu

export function normaliseSearchText(text: string): string {
  return text.normalize('NFD').replace(COMBINING_MARK_PATTERN, '').toLowerCase()
}

export function matchesSearchText(searchTerm: string, candidateTexts: readonly (string | null | undefined)[]): boolean {
  const normalisedTerm = normaliseSearchText(searchTerm.trim())
  if (normalisedTerm === '') {
    return true
  }
  return candidateTexts.some((candidateText) => typeof candidateText === 'string' && normaliseSearchText(candidateText).includes(normalisedTerm))
}
