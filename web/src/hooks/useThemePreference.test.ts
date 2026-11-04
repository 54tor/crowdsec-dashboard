import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { useThemePreference } from '@/hooks/useThemePreference'

describe('useThemePreference', () => {
  afterEach(() => {
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
})
