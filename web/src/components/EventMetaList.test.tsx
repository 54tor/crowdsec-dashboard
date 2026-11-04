import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'
import { EventMetaList } from '@/components/EventMetaList'
import en from '@/i18n/en.json'
import { BIDI_OVERRIDE_SAMPLE, JAVASCRIPT_URL, MALICIOUS_SCENARIO } from '@/test/fixtures'
import { prepareEnglishApp } from '@/test/pageHarness'

describe('event meta list', () => {
  beforeEach(prepareEnglishApp)

  // Event meta comes from the attacker (user agent, URL, payload): a value that
  // looks like markup must stay a text node, never become an element.
  it('rend une méta <img src=x onerror=alert(1)> comme texte', () => {
    const { container } = render(<EventMetaList meta={{ http_user_agent: MALICIOUS_SCENARIO, [MALICIOUS_SCENARIO]: 'key-is-hostile' }} />)

    expect(container.querySelector('img')).toBeNull()
    expect(screen.getAllByText(MALICIOUS_SCENARIO)).toHaveLength(2)
    expect(screen.getByText('key-is-hostile')).toBeInTheDocument()
  })

  // No link detection: a javascript: URL in a value is plain text, so no anchor
  // and no href can ever carry it.
  it('rend une URL javascript: comme texte sans lien', () => {
    const { container } = render(<EventMetaList meta={{ target_uri: JAVASCRIPT_URL }} />)

    expect(container.querySelector('a')).toBeNull()
    expect(container.querySelector('[href]')).toBeNull()
    expect(screen.getByText(JAVASCRIPT_URL)).toBeInTheDocument()
  })

  // A U+202E override inside a value must not reorder the next cells: each key
  // and value sits in its own bidi isolate.
  it('isolatesBidiOverrideInKeysAndValues', () => {
    const { container } = render(<EventMetaList meta={{ [BIDI_OVERRIDE_SAMPLE]: BIDI_OVERRIDE_SAMPLE }} />)

    const isolatedTexts = container.querySelectorAll('bdi')
    expect(isolatedTexts).toHaveLength(2)
    isolatedTexts.forEach((isolatedText) => expect(isolatedText.textContent).toBe(BIDI_OVERRIDE_SAMPLE))
    expect(container.querySelector('dt bdi')).not.toBeNull()
    expect(container.querySelector('dd bdi')).not.toBeNull()
  })

  it('breaksLongUnbrokenValues', () => {
    const longValue = 'a'.repeat(4096)
    render(<EventMetaList meta={{ payload: longValue }} />)

    expect(screen.getByText(longValue)).toHaveClass('whitespace-pre-wrap', '[overflow-wrap:anywhere]')
  })

  it('showsEmptyStateWithoutMeta', () => {
    render(<EventMetaList meta={{}} />)

    expect(screen.getByText(en.alertDetail.noMeta)).toBeInTheDocument()
  })
})
