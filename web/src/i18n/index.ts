import i18next from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from './en.json'
import fr from './fr.json'

export const SUPPORTED_LANGUAGES = ['fr', 'en'] as const
export type Language = (typeof SUPPORTED_LANGUAGES)[number]

export const LANGUAGE_STORAGE_KEY = 'lang'

function isSupportedLanguage(candidate: string | null): candidate is Language {
  return SUPPORTED_LANGUAGES.some((language) => language === candidate)
}

function readStoredLanguage(): string | null {
  try {
    return localStorage.getItem(LANGUAGE_STORAGE_KEY)
  } catch {
    return null
  }
}

export function detectLanguage(): Language {
  const storedLanguage = readStoredLanguage()
  if (isSupportedLanguage(storedLanguage)) {
    return storedLanguage
  }
  return navigator.language.toLowerCase().startsWith('fr') ? 'fr' : 'en'
}

export async function setLanguage(language: Language): Promise<void> {
  try {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, language)
  } catch {
    void 0
  }
  await i18next.changeLanguage(language)
}

function syncDocument(): void {
  document.documentElement.lang = i18next.language
  document.title = i18next.t('app.title')
}

export function errorMessage(error: unknown): string {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'unknown'
  return i18next.t(`errors.${code}`, { defaultValue: i18next.t('errors.unknown') })
}

export function initI18n(): Promise<unknown> {
  i18next.on('languageChanged', syncDocument)
  return i18next.use(initReactI18next).init({
    lng: detectLanguage(),
    fallbackLng: 'en',
    resources: { fr: { translation: fr }, en: { translation: en } },
    interpolation: { escapeValue: false },
  })
}

export default i18next
