import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'
import { resetThemePreferenceStore } from '../hooks/useThemePreference'
import { installMatchMediaStub, resetMatchMediaStub } from './matchMedia'

installMatchMediaStub()

afterEach(() => {
  cleanup()
  localStorage.clear()
  resetMatchMediaStub()
  // The theme store remembers the last choice at module level; drop it between tests.
  resetThemePreferenceStore()
})
