export function isTimeoutError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'cscli_timeout'
}
