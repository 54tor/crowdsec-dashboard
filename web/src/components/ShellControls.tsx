import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { useAuth } from '@/auth/useAuth'
import { Icon } from '@/components/Icon'
import { LanguageSwitch } from '@/components/LanguageSwitch'
import { ThemeSwitch } from '@/components/ThemeSwitch'
import { Button } from '@/components/ui/button'

export function ShellControls({ onLogout }: { onLogout: () => Promise<void> }) {
  const { t } = useTranslation()
  const { accountName } = useAuth()
  return (
    <div className="grid gap-2.5 border-t pt-4">
      <p className="px-0.5 font-condensed text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
        {t('shell.account')}
      </p>
      <Link
        to="/account/security"
        className="flex min-h-10 items-center rounded-md px-2.5 text-sm font-medium focus-ring hover:bg-secondary"
      >
        <span className="min-w-0 truncate">{accountName ?? t('nav.accountSecurity')}</span>
      </Link>
      <div className="flex flex-wrap gap-2">
        <LanguageSwitch />
        <ThemeSwitch />
      </div>
      <Button variant="ghost" size="sm" className="justify-start" onClick={() => void onLogout()}>
        <Icon name="logout" className="size-3.5" />
        {t('logout')}
      </Button>
    </div>
  )
}
