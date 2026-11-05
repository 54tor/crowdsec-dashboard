export const PALETTE_DEBOUNCE_MILLISECONDS = 250
export const PALETTE_RESULTS_PER_CATEGORY = 5

function pathWithParameter(path: string, parameterName: string, parameterValue: string): string {
  const parameters = new URLSearchParams({ [parameterName]: parameterValue })
  return `${path}?${parameters.toString()}`
}

export function alertsSearchPath(term: string): string {
  return pathWithParameter('/alerts', 'q', term)
}

export function decisionsSearchPath(term: string): string {
  return pathWithParameter('/decisions', 'q', term)
}

export function engineAlertsPath(engineName: string): string {
  return pathWithParameter('/alerts', 'engine', engineName)
}
