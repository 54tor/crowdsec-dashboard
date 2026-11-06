import { useState } from 'react'

export const ADVANCED_MODE_STORAGE_KEY = 'config-advanced-mode'

function readStoredAdvancedMode(): boolean {
  try {
    return localStorage.getItem(ADVANCED_MODE_STORAGE_KEY) === 'on'
  } catch {
    return false
  }
}

function storeAdvancedMode(isEnabled: boolean): void {
  try {
    localStorage.setItem(ADVANCED_MODE_STORAGE_KEY, isEnabled ? 'on' : 'off')
  } catch {
    void 0
  }
}

export function useAdvancedMode(): [boolean, (isEnabled: boolean) => void] {
  const [isAdvancedMode, setIsAdvancedMode] = useState(readStoredAdvancedMode)
  function changeAdvancedMode(isEnabled: boolean) {
    setIsAdvancedMode(isEnabled)
    storeAdvancedMode(isEnabled)
  }
  return [isAdvancedMode, changeAdvancedMode]
}
