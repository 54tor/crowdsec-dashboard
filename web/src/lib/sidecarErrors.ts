import i18next, { errorMessage } from '@/i18n'

const UNUSABLE_SIDECAR_CODE = 'engine_secret_unreadable'

function hasErrorCode(error: unknown, expectedCode: string): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === expectedCode
}

export function sidecarErrorMessage(error: unknown): string {
  if (hasErrorCode(error, UNUSABLE_SIDECAR_CODE)) {
    return i18next.t('engines.sidecar.unusable')
  }
  return errorMessage(error)
}
