export function isTimeoutError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'cscli_timeout'
}

export function isInvalidRequestError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'invalid_request'
}
