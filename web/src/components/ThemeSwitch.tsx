import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import type { IconName } from '@/components/iconSources'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useThemePreference } from '@/hooks/useThemePreference'
import type { ThemePreference } from '@/lib/themePreference'

const THEME_CHOICES: readonly { preference: ThemePreference; icon: IconName }[] = [
  { preference: 'system', icon: 'contrast' },
  { preference: 'light', icon: 'light_mode' },
  { preference: 'dark', icon: 'dark_mode' },
]

function iconForPreference(preference: ThemePreference): IconName {
  const matchingChoice = THEME_CHOICES.find((themeChoice) => themeChoice.preference === preference)
  return matchingChoice?.icon ?? 'contrast'
}

function isThemePreference(choiceValue: string): choiceValue is ThemePreference {
  return THEME_CHOICES.some((themeChoice) => themeChoice.preference === choiceValue)
}

export function ThemeSwitch() {
  const { t } = useTranslation()
  const { themePreference, changeThemePreference } = useThemePreference()

  function selectThemePreference(choiceValue: string) {
    if (isThemePreference(choiceValue)) {
      changeThemePreference(choiceValue)
    }
  }

  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" aria-label={t('theme.label')}>
          <Icon name={iconForPreference(themePreference)} className="size-3.5" />
          {t(`theme.${themePreference}`)}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuRadioGroup value={themePreference} onValueChange={selectThemePreference}>
          {THEME_CHOICES.map((themeChoice) => (
            <DropdownMenuRadioItem key={themeChoice.preference} value={themeChoice.preference}>
              <Icon name={themeChoice.icon} className="size-4" />
              {t(`theme.${themeChoice.preference}`)}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
