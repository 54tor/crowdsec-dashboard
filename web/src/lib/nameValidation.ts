const RESOURCE_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/
const HUB_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}(\/[a-zA-Z0-9][a-zA-Z0-9._-]{0,63})?$/

export type NameError = 'invalid_name'

export function validateResourceName(name: string): NameError | null {
  return RESOURCE_NAME_PATTERN.test(name) ? null : 'invalid_name'
}

export function validateHubName(name: string): NameError | null {
  return HUB_NAME_PATTERN.test(name) ? null : 'invalid_name'
}
