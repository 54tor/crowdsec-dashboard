import ipaddr from 'ipaddr.js'
import { isValidTarget } from '@/lib/filterValidation'

const MAX_TARGET_LENGTH = 43
const MIN_IPV4_BAN_PREFIX = 8
const MIN_IPV6_BAN_PREFIX = 32
const MAX_REASON_LENGTH = 200
const DURATION_PATTERN = /^[0-9]{1,4}[smhd]$/
const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u

export type BanFieldError = 'invalid_target' | 'invalid_duration' | 'invalid_reason'

function isIpv4MappedAddress(address: string): boolean {
  return ipaddr.IPv6.isValid(address) && ipaddr.IPv6.parse(address).isIPv4MappedAddress()
}

function isPrefixWideEnough(address: string, prefix: string): boolean {
  const minimumPrefix = ipaddr.IPv4.isValidFourPartDecimal(address) ? MIN_IPV4_BAN_PREFIX : MIN_IPV6_BAN_PREFIX
  return Number(prefix) >= minimumPrefix
}

export function validateBanTarget(target: string): BanFieldError | null {
  if (target.length > MAX_TARGET_LENGTH || !isValidTarget(target)) {
    return 'invalid_target'
  }
  const [address, prefix] = target.split('/')
  if (isIpv4MappedAddress(address)) {
    return 'invalid_target'
  }
  if (prefix !== undefined && !isPrefixWideEnough(address, prefix)) {
    return 'invalid_target'
  }
  return null
}

export function validateBanDuration(duration: string): BanFieldError | null {
  return DURATION_PATTERN.test(duration) ? null : 'invalid_duration'
}

export function validateBanReason(reason: string): BanFieldError | null {
  const isTooLong = [...reason].length > MAX_REASON_LENGTH
  return isTooLong || CONTROL_CHARACTER_PATTERN.test(reason) ? 'invalid_reason' : null
}
