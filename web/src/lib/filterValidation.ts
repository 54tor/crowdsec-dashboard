import ipaddr from 'ipaddr.js'
import type { ListFilters } from '@/api/types'

export type FilterErrors = Partial<Record<keyof ListFilters, 'scenarioInvalid' | 'ipInvalid' | 'sinceInvalid'>>

const SCENARIO_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$/
const DURATION_PATTERN = /^[0-9]{1,4}[smhd]$/
const PREFIX_PATTERN = /^[0-9]{1,3}$/
const IPV4_MAX_PREFIX = 32
const IPV6_MAX_PREFIX = 128

function isValidAddress(address: string): boolean {
  return ipaddr.IPv4.isValidFourPartDecimal(address) || (!address.includes('%') && ipaddr.IPv6.isValid(address))
}

function maxPrefixFor(address: string): number {
  return ipaddr.IPv4.isValidFourPartDecimal(address) ? IPV4_MAX_PREFIX : IPV6_MAX_PREFIX
}

export function isValidTarget(target: string): boolean {
  const [address, prefix, ...rest] = target.split('/')
  if (rest.length > 0 || !isValidAddress(address)) {
    return false
  }
  if (prefix === undefined) {
    return true
  }
  return PREFIX_PATTERN.test(prefix) && Number(prefix) <= maxPrefixFor(address)
}

export function validateFilters(filters: ListFilters): FilterErrors {
  const errors: FilterErrors = {}
  if (filters.scenario !== '' && !SCENARIO_PATTERN.test(filters.scenario)) {
    errors.scenario = 'scenarioInvalid'
  }
  if (filters.ip !== '' && !isValidTarget(filters.ip)) {
    errors.ip = 'ipInvalid'
  }
  if (filters.since !== '' && !DURATION_PATTERN.test(filters.since)) {
    errors.since = 'sinceInvalid'
  }
  return errors
}
