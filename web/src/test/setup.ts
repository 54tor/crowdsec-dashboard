import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'
import { installMatchMediaStub, resetMatchMediaStub } from './matchMedia'

installMatchMediaStub()

afterEach(() => {
  cleanup()
  localStorage.clear()
  resetMatchMediaStub()
})
