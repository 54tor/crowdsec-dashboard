import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'
import type { AlertEvent } from '@/api/types'
import { AppSecSummary } from '@/components/AppSecSummary'
import en from '@/i18n/en.json'
import { BIDI_OVERRIDE_SAMPLE, JAVASCRIPT_URL, MALICIOUS_SCENARIO } from '@/test/fixtures'
import { prepareEnglishApp } from '@/test/pageHarness'

function eventWithMeta(meta: Record<string, string>): AlertEvent {
  return { timestamp: '2026-10-31T10:15:00Z', meta }
}

describe('appsec summary', () => {
  beforeEach(prepareEnglishApp)

  // The request URI is chosen by the attacker: markup in it must stay a text
  // node, so no img element (and no onerror handler) can ever be created.
  it('rend une target_uri hostile comme texte', () => {
    const { container } = render(<AppSecSummary events={[eventWithMeta({ target_uri: MALICIOUS_SCENARIO, uri: MALICIOUS_SCENARIO })]} />)

    expect(container.querySelector('img')).toBeNull()
    expect(screen.getAllByText(MALICIOUS_SCENARIO)).toHaveLength(2)
  })

  // There is no link detection anywhere in the summary: a javascript: value
  // never becomes an anchor or an href.
  it('ne rend jamais rule_name javascript: en lien', () => {
    const { container } = render(<AppSecSummary events={[eventWithMeta({ rule_name: JAVASCRIPT_URL })]} />)

    expect(container.querySelector('a')).toBeNull()
    expect(container.querySelector('[href]')).toBeNull()
    expect(screen.getByText(JAVASCRIPT_URL)).toBeInTheDocument()
  })

  // A U+202E override must not reorder the next rows: the value's direct
  // parent is a native bdi isolate and the text reaches the DOM untouched.
  it('isole chaque valeur dans un élément bdi', () => {
    const { container } = render(<AppSecSummary events={[eventWithMeta({ rule_name: BIDI_OVERRIDE_SAMPLE, target_host: 'example.com' })]} />)

    const overrideValue = screen.getByText(BIDI_OVERRIDE_SAMPLE)
    expect(overrideValue.tagName).toBe('BDI')
    expect(overrideValue.textContent).toBe(BIDI_OVERRIDE_SAMPLE)
    expect(container.querySelectorAll('dd')).toHaveLength(2)
    container.querySelectorAll('dd').forEach((valueCell) => expect(valueCell.querySelector('bdi')).not.toBeNull())
  })

  // The full 4096-byte value stays in the DOM (copyable); only its box is
  // bounded and scrollable, and the text wraps anywhere.
  it('tronque visuellement une URI de 4096 octets sans perte de texte', () => {
    const longUri = `/${'a'.repeat(4095)}`
    render(<AppSecSummary events={[eventWithMeta({ uri: longUri })]} />)

    const uriValue = screen.getByText(longUri)
    expect(uriValue.textContent).toHaveLength(4096)
    expect(uriValue).toHaveClass('whitespace-pre-wrap', 'break-all')
    expect(uriValue.closest('dd')).toHaveClass('max-h-24', 'overflow-y-auto')
  })

  // Only the AppSec keys present in an event are listed; unrelated keys and
  // events without any AppSec key produce nothing.
  it('ignore les clés absentes', () => {
    const { container } = render(
      <AppSecSummary events={[eventWithMeta({ rule_name: 'crowdsecurity/vpatch-env-access', source_ip: '203.0.113.7' }), eventWithMeta({ service: 'ssh' })]} />,
    )

    expect(container.querySelectorAll('dl')).toHaveLength(1)
    expect(container.querySelectorAll('dt')).toHaveLength(1)
    expect(screen.getByText(en.appsec.fields.rule_name)).toBeInTheDocument()
    expect(screen.queryByText(en.appsec.fields.target_uri)).toBeNull()
    expect(screen.queryByText('203.0.113.7')).toBeNull()
  })

  it('rendsNothingWithoutAnyAppSecKey', () => {
    const { container } = render(<AppSecSummary events={[eventWithMeta({ service: 'ssh' })]} />)

    expect(container).toBeEmptyDOMElement()
  })
})
