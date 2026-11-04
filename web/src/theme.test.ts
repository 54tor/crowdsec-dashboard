import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useThemePreference } from '@/hooks/useThemePreference'
import { setSystemPrefersDark } from '@/test/matchMedia'
import { followThemePreference } from '@/theme'

function makeEveryStorageAccessThrow(): void {
  for (const storageMethodName of ['getItem', 'setItem'] as const) {
    vi.spyOn(Storage.prototype, storageMethodName).mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError')
    })
  }
}

describe('followThemePreference', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    document.documentElement.classList.remove('dark')
  })

  // Private browsing can make localStorage throw: storage then always reads
  // "system", so a system change used to override the theme chosen in the switch.
  it('keepsTheChosenThemeWhenTheSystemChangesAndStorageThrows', () => {
    makeEveryStorageAccessThrow()
    followThemePreference()
    const themeSwitch = renderHook(() => useThemePreference())
    act(() => themeSwitch.result.current.changeThemePreference('light'))

    setSystemPrefersDark(true)

    expect(document.documentElement).not.toHaveClass('dark')
  })

  it('followsTheSystemWhenTheChoiceIsSystem', () => {
    followThemePreference()

    setSystemPrefersDark(true)

    expect(document.documentElement).toHaveClass('dark')
  })
})
