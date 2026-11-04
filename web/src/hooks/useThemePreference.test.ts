import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useThemePreference } from '@/hooks/useThemePreference'

describe('useThemePreference', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    document.documentElement.classList.remove('dark')
  })

  // The rail and the mobile Plus sheet each render a theme switch: a choice
  // made in one must show at once in the other.
  it('twoSwitchesShareTheSameChoice', () => {
    const firstSwitch = renderHook(() => useThemePreference())
    const secondSwitch = renderHook(() => useThemePreference())

    act(() => firstSwitch.result.current.changeThemePreference('dark'))

    expect(secondSwitch.result.current.themePreference).toBe('dark')
  })

  // Private browsing can make localStorage throw: the page still applies the
  // chosen theme, so the switch must show that choice and not fall back to System.
  it('keepsChosenPreferenceWhenStorageThrows', () => {
    const storageFailure = new DOMException('blocked', 'SecurityError')
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw storageFailure
    })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw storageFailure
    })
    const themeSwitch = renderHook(() => useThemePreference())

    act(() => themeSwitch.result.current.changeThemePreference('dark'))

    expect(themeSwitch.result.current.themePreference).toBe('dark')
    expect(document.documentElement).toHaveClass('dark')
  })
})
