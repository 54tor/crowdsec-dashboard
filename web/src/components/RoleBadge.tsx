import { useTranslation } from 'react-i18next'
import { useAuth } from '@/auth/useAuth'

export function RoleBadge() {
  const { t } = useTranslation()
  const { accountRole } = useAuth()
  if (accountRole === null) {
    return null
  }
  return (
    <span className="rounded border px-1.5 py-px font-condensed text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
      {t(`shell.role.${accountRole}`)}
    </span>
  )
}
