import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { BrandMark } from '@/components/BrandMark'
import { LanguageSwitch } from '@/components/LanguageSwitch'
import { ThemeSwitch } from '@/components/ThemeSwitch'
import { Card, CardContent, CardDescription, CardHeader } from '@/components/ui/card'

interface AuthPageShellProps {
  title: string
  description: string
  isLoading?: boolean
  children?: ReactNode
}

export function AuthPageShell({ title, description, isLoading = false, children }: AuthPageShellProps) {
  const { t } = useTranslation()
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-6 bg-background p-4 text-foreground">
      <div className="absolute top-4 right-4 flex gap-2">
        <LanguageSwitch />
        <ThemeSwitch />
      </div>
      <BrandMark />
      <Card className="w-full max-w-sm">
        <CardHeader>
          <h1 className="font-condensed text-xl font-semibold">{title}</h1>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div role="status" className="text-sm text-muted-foreground">
              {t('common.loading')}
            </div>
          ) : (
            children
          )}
        </CardContent>
      </Card>
    </main>
  )
}
