import { applyThemePreference, DARK_SCHEME_QUERY, readThemePreference } from './lib/themePreference'

function reapplyWhenFollowingSystem(): void {
  const currentPreference = readThemePreference()
  if (currentPreference === 'system') {
    applyThemePreference(currentPreference)
  }
}

export function followThemePreference(): void {
  applyThemePreference(readThemePreference())
  window.matchMedia(DARK_SCHEME_QUERY).addEventListener('change', reapplyWhenFollowingSystem)
}
