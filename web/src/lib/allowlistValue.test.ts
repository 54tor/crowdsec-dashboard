import { describe, expect, it } from 'vitest'
import { allowlistTextError, wideRangeConfirmationValue } from '@/lib/allowlistValue'

// The thresholds mirror backend netparse: confirmation below /24 (IPv4) and /48 (IPv6),
// the expected confirmation being the canonical (masked, lowercase, compressed) prefix.
describe('wideRangeConfirmationValue', () => {
  it('exigeUneConfirmationPourUnSlash23Ipv4MaisPasPourUnSlash24', () => {
    expect(wideRangeConfirmationValue('192.0.3.9/23')).toBe('192.0.2.0/23')
    expect(wideRangeConfirmationValue('192.0.2.9/24')).toBeNull()
  })

  it('exigeUneConfirmationPourUnSlash47Ipv6MaisPasPourUnSlash48', () => {
    expect(wideRangeConfirmationValue('2001:db8:1::/47')).toBe('2001:db8::/47')
    expect(wideRangeConfirmationValue('2001:db8:1::/48')).toBeNull()
  })

  it('canoniseUneIpv6EnMajusculesEtNonCompressee', () => {
    expect(wideRangeConfirmationValue('2001:0DB8:0000:0000:0000:0000:0000:0001/32')).toBe('2001:db8::/32')
  })

  it('demasqueUneIpv4MappeeAvantDeComparerAuSeuil', () => {
    expect(wideRangeConfirmationValue('::ffff:10.1.2.3/104')).toBe('10.0.0.0/8')
    expect(wideRangeConfirmationValue('::ffff:10.1.2.3/120')).toBeNull()
  })

  it('neDemandeRienPourUneAdresseSeuleOuUneValeurInvalide', () => {
    expect(wideRangeConfirmationValue('10.0.0.1')).toBeNull()
    expect(wideRangeConfirmationValue('2001:db8::1')).toBeNull()
    expect(wideRangeConfirmationValue('not-an-address/8')).toBeNull()
  })

  it('ignoreLesEspacesAutourDeLaValeur', () => {
    expect(wideRangeConfirmationValue('  10.0.5.7/16  ')).toBe('10.0.0.0/16')
  })
})

describe('allowlistTextError', () => {
  it('accepteUnTexteOrdinaireDe256Octets', () => {
    expect(allowlistTextError('a'.repeat(256))).toBeNull()
  })

  it('compteLesOctetsUtf8EtNonLesCaracteres', () => {
    // "é" is two bytes in UTF-8: 129 characters make 258 bytes.
    expect(allowlistTextError('é'.repeat(129))).toBe('textTooLong')
  })

  it('refuseUnTiretInitialEtLesCaracteresDeControle', () => {
    expect(allowlistTextError('-rm')).toBe('textLeadingDash')
    expect(allowlistTextError('line\nbreak')).toBe('textInvalidCharacter')
    expect(allowlistTextError(`zero${String.fromCodePoint(0x200b)}width`)).toBe('textInvalidCharacter')
  })
})
