export interface SearchNavigationState {
  searchNonce: number
}

export function searchNonceOf(locationState: unknown): number | undefined {
  if (typeof locationState !== 'object' || locationState === null || !('searchNonce' in locationState)) {
    return undefined
  }
  const { searchNonce } = locationState
  return typeof searchNonce === 'number' ? searchNonce : undefined
}
