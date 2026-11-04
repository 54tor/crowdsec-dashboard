import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { SUPPORTED_LANGUAGES, setLanguage, type Language } from '@/i18n'

export function LanguageSwitch() {
  const { t, i18n } = useTranslation()
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" aria-label={t('language.label')}>
          <Icon name="translate" className="size-3.5" />
          {i18n.language.toUpperCase()}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuRadioGroup
          value={i18n.language}
          onValueChange={(language) => void setLanguage(language as Language)}
        >
          {SUPPORTED_LANGUAGES.map((language) => (
            <DropdownMenuRadioItem key={language} value={language}>
              {t(`language.${language}`)}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
