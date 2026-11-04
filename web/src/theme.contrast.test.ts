import Color from 'colorjs.io'
import { describe, expect, it } from 'vitest'
import indexCssSource from './index.css?raw'

type ThemeTokens = Record<string, string>

const WCAG_TEXT_MINIMUM = 4.5
const WCAG_NON_TEXT_MINIMUM = 3
const STATE_TINT_PROPORTION = 0.14
const STATE_TOKEN_NAMES = ['critical', 'warning', 'info', 'nominal']

// Reads the custom properties declared in the first block opened by `selector {`.
// Only plain `--name: value;` declarations are kept, so derived values such as
// color-mix() tints stay in the map but are never compared directly.
function parseTokenBlock(selector: string): ThemeTokens {
  const blockStart = indexCssSource.indexOf(`${selector} {`)
  expect(blockStart, `missing ${selector} block in index.css`).toBeGreaterThanOrEqual(0)
  const blockEnd = indexCssSource.indexOf('}', blockStart)
  const blockBody = indexCssSource.slice(blockStart, blockEnd)
  const tokens: ThemeTokens = {}
  for (const declarationMatch of blockBody.matchAll(/--([\w-]+):\s*([^;]+);/g)) {
    const [, tokenName, tokenValue] = declarationMatch
    tokens[tokenName] = tokenValue.trim()
  }
  return tokens
}

const tokensByTheme: Record<string, ThemeTokens> = {
  light: parseTokenBlock(':root'),
  dark: parseTokenBlock('.dark'),
}

function contrastBetween(foregroundValue: string, backgroundValue: string): number {
  return new Color(foregroundValue).contrast(new Color(backgroundValue), 'WCAG21')
}

// Mirrors `color-mix(in srgb, var(--state) 14%, var(--card))`: colorjs mixes
// towards its second argument, so the card comes first and the state second.
function stateTintOnCard(stateValue: string, cardValue: string): string {
  const tintColor = Color.mix(cardValue, stateValue, STATE_TINT_PROPORTION, { space: 'srgb' })
  return tintColor.toString({ format: 'hex' })
}

describe.each(['light', 'dark'])('%s theme tokens', (themeName) => {
  const themeTokens = tokensByTheme[themeName]

  it('textMeetsAaOnEverySurface', () => {
    const textPairs: Array<[string, string]> = [
      ['foreground', 'background'],
      ['foreground', 'card'],
      ['foreground', 'secondary'],
      ['muted-foreground', 'card'],
      ['muted-foreground', 'secondary'],
      ['primary-foreground', 'primary'],
      ['on-critical', 'critical-fill'],
    ]
    for (const [foregroundName, backgroundName] of textPairs) {
      const measuredContrast = contrastBetween(themeTokens[foregroundName], themeTokens[backgroundName])
      expect(measuredContrast, `${foregroundName} on ${backgroundName}`).toBeGreaterThanOrEqual(WCAG_TEXT_MINIMUM)
    }
    for (const stateName of STATE_TOKEN_NAMES) {
      const stateValue = themeTokens[stateName]
      const tintValue = stateTintOnCard(stateValue, themeTokens.card)
      expect(contrastBetween(stateValue, themeTokens.card), `${stateName} on card`).toBeGreaterThanOrEqual(WCAG_TEXT_MINIMUM)
      expect(contrastBetween(stateValue, tintValue), `${stateName} on its tint`).toBeGreaterThanOrEqual(WCAG_TEXT_MINIMUM)
    }
  })

  it('fieldBorderMeetsNonTextContrast', () => {
    expect(contrastBetween(themeTokens.input, themeTokens.card)).toBeGreaterThanOrEqual(WCAG_NON_TEXT_MINIMUM)
    expect(contrastBetween(themeTokens.input, themeTokens.background)).toBeGreaterThanOrEqual(WCAG_NON_TEXT_MINIMUM)
  })

  it('focusRingStaysVisible', () => {
    const amberRingContrast = contrastBetween(themeTokens.ring, themeTokens.background)
    const inkInnerRingContrast = contrastBetween(themeTokens['focus-inner'], themeTokens.background)
    expect(Math.max(amberRingContrast, inkInnerRingContrast)).toBeGreaterThanOrEqual(WCAG_NON_TEXT_MINIMUM)
  })
})

describe('theme stylesheet', () => {
  it('usesTheApprovedAdjustments', () => {
    expect(tokensByTheme.dark.input).toBe('#6a6a72')
    expect(tokensByTheme.light.nominal).toBe('#1a7038')
  })

  it('declaresReducedMotionAndFocusRing', () => {
    expect(indexCssSource).toContain('@media (prefers-reduced-motion: reduce)')
    expect(indexCssSource).toContain('@utility focus-ring')
    expect(indexCssSource).toContain('box-shadow: 0 0 0 2px var(--focus-inner)')
  })
})
