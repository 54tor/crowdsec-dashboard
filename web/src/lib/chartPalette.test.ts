import { afterEach, describe, expect, it } from 'vitest'
import { readChartPalette } from '@/lib/chartPalette'

const THEME_VARIABLES_READ_BY_THE_CHART = ['--muted-foreground', '--border', '--info'] as const

describe('chart palette', () => {
  afterEach(() => {
    for (const variableName of THEME_VARIABLES_READ_BY_THE_CHART) {
      document.documentElement.style.removeProperty(variableName)
    }
  })

  // The chart used hard-coded colours that ignored the theme tokens; it must
  // read them from the document and see a new value after a theme change.
  it('readsChartColoursFromThemeVariables', () => {
    document.documentElement.style.setProperty('--muted-foreground', '#55524a')
    document.documentElement.style.setProperty('--border', '#dad7ce')
    document.documentElement.style.setProperty('--info', '#2a4f9f')

    expect(readChartPalette()).toEqual({ text: '#55524a', grid: '#dad7ce', bar: '#2a4f9f' })

    document.documentElement.style.setProperty('--info', '#8fb4ff')

    expect(readChartPalette().bar).toBe('#8fb4ff')
  })
})
