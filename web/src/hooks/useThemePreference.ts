import { useCallback, useState } from 'react'
import { readThemePreference, storeThemePreference, type ThemePreference } from '../lib/themePreference'

export function useThemePreference(): {
  themePreference: ThemePreference
  changeThemePreference: (preference: ThemePreference) => void
} {
  const [themePreference, setThemePreference] = useState<ThemePreference>(readThemePreference)

  const changeThemePreference = useCallback((preference: ThemePreference) => {
    storeThemePreference(preference)
    setThemePreference(preference)
  }, [])

  return { themePreference, changeThemePreference }
}
