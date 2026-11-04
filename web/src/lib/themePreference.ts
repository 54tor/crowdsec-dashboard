export const THEME_STORAGE_KEY = 'theme-preference'

export type ThemePreference = 'system' | 'light' | 'dark'

export const DARK_SCHEME_QUERY = '(prefers-color-scheme: dark)'

const THEME_PREFERENCES: readonly ThemePreference[] = ['system', 'light', 'dark']

function isThemePreference(storedValue: string | null): storedValue is ThemePreference {
  return THEME_PREFERENCES.some((themePreference) => themePreference === storedValue)
}

function readStoredValue(): string | null {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY)
  } catch {
    return null
  }
}

function persistThemePreference(preference: ThemePreference): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, preference)
  } catch {
    return
  }
}

export function readThemePreference(): ThemePreference {
  const storedValue = readStoredValue()
  if (isThemePreference(storedValue)) {
    return storedValue
  }
  return 'system'
}

export function storeThemePreference(preference: ThemePreference): void {
  persistThemePreference(preference)
  applyThemePreference(preference)
}

export function resolveIsDark(preference: ThemePreference, systemPrefersDark: boolean): boolean {
  if (preference === 'system') {
    return systemPrefersDark
  }
  return preference === 'dark'
}

export function applyThemePreference(preference: ThemePreference): void {
  const systemPrefersDark = window.matchMedia(DARK_SCHEME_QUERY).matches
  const isDark = resolveIsDark(preference, systemPrefersDark)
  const rootElement = document.documentElement
  rootElement.classList.toggle('dark', isDark)
  rootElement.style.colorScheme = isDark ? 'dark' : 'light'
}
