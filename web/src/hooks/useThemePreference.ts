import { useSyncExternalStore } from 'react'
import { readThemePreference, storeThemePreference, type ThemePreference } from '../lib/themePreference'

const preferenceListeners = new Set<() => void>()

function subscribeToPreference(onPreferenceChange: () => void): () => void {
  preferenceListeners.add(onPreferenceChange)
  return () => preferenceListeners.delete(onPreferenceChange)
}

function changeThemePreference(preference: ThemePreference): void {
  storeThemePreference(preference)
  preferenceListeners.forEach((notifyListener) => notifyListener())
}

export function useThemePreference(): {
  themePreference: ThemePreference
  changeThemePreference: (preference: ThemePreference) => void
} {
  const themePreference = useSyncExternalStore(subscribeToPreference, readThemePreference)
  return { themePreference, changeThemePreference }
}
