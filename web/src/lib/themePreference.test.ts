import { afterEach, describe, expect, it, vi } from 'vitest'
import themeInitScriptSource from '../../public/theme-init.js?raw'
import { setSystemPrefersDark } from '../test/matchMedia'
import { applyThemePreference, readThemePreference, storeThemePreference } from './themePreference'

const rootElement = document.documentElement

function makeStorageThrow(storageMethodName: 'getItem' | 'setItem'): void {
  vi.spyOn(Storage.prototype, storageMethodName).mockImplementation(() => {
    throw new Error('storage disabled')
  })
}

// The pre-paint script is served as-is from public/, so it is run here the same
// way the browser runs a classic script: as plain source, outside any module.
function runThemeInitScript(): void {
  new Function(themeInitScriptSource)()
}

afterEach(() => {
  vi.restoreAllMocks()
  rootElement.classList.remove('dark')
  rootElement.style.colorScheme = ''
})

describe('theme preference', () => {
  it('defaultsToSystem', () => {
    expect(readThemePreference()).toBe('system')
  })

  it('persistsTheChosenTheme', () => {
    storeThemePreference('dark')

    expect(localStorage.getItem('theme-preference')).toBe('dark')
    expect(readThemePreference()).toBe('dark')
    expect(rootElement).toHaveClass('dark')
  })

  it('followsSystemWhenPreferenceIsSystem', () => {
    setSystemPrefersDark(true)

    applyThemePreference('system')

    expect(rootElement).toHaveClass('dark')
    expect(rootElement.style.colorScheme).toBe('dark')
  })

  it('fallsBackToSystemWhenStorageThrows', () => {
    makeStorageThrow('getItem')
    makeStorageThrow('setItem')

    expect(readThemePreference()).toBe('system')
    expect(() => storeThemePreference('light')).not.toThrow()
  })

  it('appliesStoredDarkChoiceBeforeReactMounts', () => {
    localStorage.setItem('theme-preference', 'dark')

    runThemeInitScript()

    expect(rootElement).toHaveClass('dark')
    expect(rootElement.style.colorScheme).toBe('dark')

    rootElement.classList.remove('dark')
    makeStorageThrow('getItem')

    expect(runThemeInitScript).not.toThrow()
    expect(rootElement).not.toHaveClass('dark')
  })
})
