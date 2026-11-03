import ipaddr from 'ipaddr.js'

const IPV4_MAPPED_PREFIX_BITS = 96
const MIN_IPV4_CONFIRM_PREFIX_BITS = 24
const MIN_IPV6_CONFIRM_PREFIX_BITS = 48
const ALLOWLIST_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]{0,31}$/
const ALLOWLIST_EXPIRATION_PATTERN = /^[1-9][0-9]{0,3}[hd]$/

function canonicalPrefix(rawValue: string): { canonicalValue: string; prefixBits: number; isIpv4: boolean } | null {
  if (!rawValue.includes('/') || !ipaddr.isValidCIDR(rawValue)) {
    return null
  }
  const [parsedAddress, parsedBits] = ipaddr.parseCIDR(rawValue)
  let address = parsedAddress
  let prefixBits = parsedBits
  if (address instanceof ipaddr.IPv6 && address.isIPv4MappedAddress() && prefixBits >= IPV4_MAPPED_PREFIX_BITS) {
    address = address.toIPv4Address()
    prefixBits -= IPV4_MAPPED_PREFIX_BITS
  }
  const networkAddress =
    address instanceof ipaddr.IPv4
      ? ipaddr.IPv4.networkAddressFromCIDR(`${address.toString()}/${prefixBits}`)
      : ipaddr.IPv6.networkAddressFromCIDR(`${address.toString()}/${prefixBits}`)
  return { canonicalValue: `${networkAddress.toString()}/${prefixBits}`, prefixBits, isIpv4: address instanceof ipaddr.IPv4 }
}

export function wideRangeConfirmationValue(rawValue: string): string | null {
  const prefix = canonicalPrefix(rawValue.trim())
  if (prefix === null) {
    return null
  }
  const minimumBits = prefix.isIpv4 ? MIN_IPV4_CONFIRM_PREFIX_BITS : MIN_IPV6_CONFIRM_PREFIX_BITS
  return prefix.prefixBits < minimumBits ? prefix.canonicalValue : null
}

export function isValidAllowlistName(name: string): boolean {
  return ALLOWLIST_NAME_PATTERN.test(name)
}

export function isValidAllowlistExpiration(expiration: string): boolean {
  return ALLOWLIST_EXPIRATION_PATTERN.test(expiration)
}
