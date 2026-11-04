import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Icon } from '@/components/Icon'
import { ICON_SOURCES } from '@/components/iconSources'

describe('Icon', () => {
  it('rendersTheOutlinedSvgHiddenFromAssistiveTech', () => {
    const { container } = render(<Icon name="logout" />)

    const iconWrapper = container.firstElementChild
    const renderedSvg = container.querySelector('svg')

    expect(renderedSvg).not.toBeNull()
    // Material Symbols files use a 960 unit grid shifted up by 960, hence the negative origin.
    expect(renderedSvg?.getAttribute('viewBox')).toBe('0 -960 960 960')
    expect(iconWrapper?.getAttribute('aria-hidden')).toBe('true')
    expect(iconWrapper?.getAttribute('data-icon')).toBe('logout')
  })

  it('everyIconNameHasASource', () => {
    const iconNames = Object.keys(ICON_SOURCES) as Array<keyof typeof ICON_SOURCES>

    expect(iconNames.length).toBeGreaterThan(0)
    for (const iconName of iconNames) {
      expect(ICON_SOURCES[iconName].startsWith('<svg'), iconName).toBe(true)
    }
  })

  it('rejectsAFreeStringAsIconName', () => {
    // The name is a closed union: a string coming from data must not type-check,
    // which keeps the injected markup limited to the bundled package files.
    // @ts-expect-error free strings are not icon names
    const elementWithFreeName = <Icon name={'<img src=x onerror=alert(1)>' as string} />

    expect(elementWithFreeName).toBeDefined()
  })
})
