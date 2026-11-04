import { useSyncExternalStore } from 'react'
import { readThemePreference, storeThemePreference, type ThemePreference } from '../lib/themePreference'

const preferenceListeners = new Set<() => void>()
let lastChosenPreference: ThemePreference | null = null

function subscribeToPreference(onPreferenceChange: () => void): () => void {
  preferenceListeners.add(onPreferenceChange)
  return () => preferenceListeners.delete(onPreferenceChange)
}

function readCurrentPreference(): ThemePreference {
  return lastChosenPreference ?? readThemePreference()
}

function changeThemePreference(preference: ThemePreference): void {
  lastChosenPreference = preference
  storeThemePreference(preference)
  preferenceListeners.forEach((notifyListener) => notifyListener())
}

export function resetThemePreferenceStore(): void {
  lastChosenPreference = null
}

export function useThemePreference(): {
  themePreference: ThemePreference
  changeThemePreference: (preference: ThemePreference) => void
} {
  const themePreference = useSyncExternalStore(subscribeToPreference, readCurrentPreference)
  return { themePreference, changeThemePreference }
}
