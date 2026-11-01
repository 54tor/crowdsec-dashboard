import { beforeEach, describe, expect, it, vi } from 'vitest'
import en from './en.json'
import fr from './fr.json'

function collectKeyPaths(node: unknown, prefix = ''): string[] {
  if (node === null || typeof node !== 'object') {
    return [prefix]
  }
  return Object.entries(node).flatMap(([childKey, childNode]) =>
    collectKeyPaths(childNode, prefix ? `${prefix}.${childKey}` : childKey),
  )
}

const KNOWN_ERROR_CODES = [
  'unauthenticated', 'forbidden', 'pending_login_expired', 'access_denied', 'second_factor_setup_not_allowed', 'too_many_pending_logins', 'invalid_credentials', 'too_many_attempts', 'cross_origin', 'not_found',
  'invalid_request', 'invalid_code', 'webauthn_failed', 'webauthn_unsupported', 'webauthn_disabled', 'second_factor_required', 'enrollment_not_started', 'second_factor_unavailable', 'invalid_account_name', 'invalid_password_length', 'invalid_enrollment_token', 'database_unavailable', 'invalid_target', 'invalid_duration', 'invalid_reason', 'confirmation_required',
  'invalid_access_rule', 'access_rule_exists', 'would_lock_out_current_client', 'geolocation_unavailable',
  'engine_exists', 'engine_not_found', 'engine_local_readonly', 'invalid_engine', 'engine_secret_required', 'engine_unreachable', 'engine_auth_failed', 'engine_blocked_address', 'engine_secret_unreadable', 'archive_write_failed', 'registry_reload_failed',
  'lapi_unavailable', 'lapi_error', 'cscli_failed', 'cscli_timeout', 'self_account', 'network', 'unknown',
]

describe('i18n', () => {
  beforeEach(() => {
    vi.resetModules()
    localStorage.clear()
  })

  it('bothLocaleFilesHaveSameKeys', () => {
    expect(collectKeyPaths(fr).sort()).toEqual(collectKeyPaths(en).sort())
  })

  it('interpolatesTheLockDurationInMinutes', async () => {
    const i18nModule = await import('./index')
    await i18nModule.initI18n()
    await i18nModule.setLanguage('en')
    expect(i18nModule.errorMessage({ code: 'account_locked', retryAfterSeconds: 61 })).toContain('2 minute')
    expect(i18nModule.errorMessage({ code: 'account_locked' })).toContain('1 minute')
  })

  it('translatesErrorCodeInBothLanguages', async () => {
    const i18nModule = await import('./index')
    await i18nModule.initI18n()
    for (const language of i18nModule.SUPPORTED_LANGUAGES) {
      await i18nModule.setLanguage(language)
      const catalog = language === 'fr' ? fr : en
      for (const errorCode of KNOWN_ERROR_CODES) {
        const expectedMessage = catalog.errors[errorCode as keyof typeof catalog.errors]
        expect(i18nModule.errorMessage({ code: errorCode })).toBe(expectedMessage)
      }
      expect(i18nModule.errorMessage({ code: 'something_new' })).toBe(catalog.errors.unknown)
      expect(i18nModule.errorMessage(new Error('boom'))).toBe(catalog.errors.unknown)
    }
  })

  it('languageChoiceSurvivesReload', async () => {
    vi.spyOn(navigator, 'language', 'get').mockReturnValue('en-US')
    const firstLoad = await import('./index')
    await firstLoad.initI18n()
    expect(firstLoad.detectLanguage()).toBe('en')
    await firstLoad.setLanguage('fr')
    expect(localStorage.getItem('lang')).toBe('fr')
    expect(document.documentElement.lang).toBe('fr')
    expect(document.title).toBe(fr.app.title)

    vi.resetModules()
    const secondLoad = await import('./index')
    expect(secondLoad.detectLanguage()).toBe('fr')
  })

  it('detectsFrenchFromBrowserLanguageElseEnglish', async () => {
    const languageSpy = vi.spyOn(navigator, 'language', 'get')
    const { detectLanguage } = await import('./index')
    languageSpy.mockReturnValue('fr-CA')
    expect(detectLanguage()).toBe('fr')
    languageSpy.mockReturnValue('de-DE')
    expect(detectLanguage()).toBe('en')
  })

  it('fallsBackToBrowserLanguageWhenStorageIsBlocked', async () => {
    vi.spyOn(navigator, 'language', 'get').mockReturnValue('fr-FR')
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError')
    })
    const { detectLanguage } = await import('./index')
    expect(detectLanguage()).toBe('fr')
    vi.restoreAllMocks()
  })
})
