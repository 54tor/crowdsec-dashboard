import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router'
import { LanguageSwitch } from '@/components/LanguageSwitch'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useAuth } from '@/auth/useAuth'
import { errorMessage } from '@/i18n'

export function Login() {
  const { t } = useTranslation()
  const { isAuthenticated, login } = useAuth()
  const [password, setPassword] = useState('')
  const loginMutation = useMutation({ mutationFn: login })

  if (isAuthenticated) {
    return <Navigate to="/alerts" replace />
  }

  function submitLogin(submitEvent: FormEvent<HTMLFormElement>) {
    submitEvent.preventDefault()
    loginMutation.mutate(password)
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="absolute right-4 top-4">
        <LanguageSwitch />
      </div>
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>
            <h1>{t('login.title')}</h1>
          </CardTitle>
          <CardDescription>{t('login.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submitLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="password">{t('login.password')}</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(changeEvent) => setPassword(changeEvent.target.value)}
              />
            </div>
            {loginMutation.isError && (
              <p role="alert" className="text-sm text-destructive">
                {errorMessage(loginMutation.error)}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={loginMutation.isPending}>
              {loginMutation.isPending ? t('login.submitting') : t('login.submit')}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
