import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'
import { resetTableDensityStore } from '../hooks/useTableDensity'
import { resetThemePreferenceStore } from '../hooks/useThemePreference'
import { installMatchMediaStub, resetMatchMediaStub } from './matchMedia'

installMatchMediaStub()

afterEach(() => {
  cleanup()
  localStorage.clear()
  resetMatchMediaStub()
  // The theme and density stores remember the last choice at module level; drop them between tests.
  resetThemePreferenceStore()
  resetTableDensityStore()
})
