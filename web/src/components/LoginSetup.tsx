import { useCallback, useState } from 'react'
import { LOGIN_SETUP_FLOW } from '@/api/loginApi'
import { RecoveryCodesStep } from '@/components/RecoveryCodesStep'
import { SecondFactorStep } from '@/components/SecondFactorStep'
import { useAuth } from '@/auth/useAuth'
import { isLoginRestartFailure } from '@/lib/loginErrors'

interface LoginSetupProps {
  methods: string[]
  onRestart(failure: unknown): void
}

export function LoginSetup({ methods, onRestart }: LoginSetupProps) {
  const { completeLoginSetup } = useAuth()
  const [isSecondFactorConfirmed, setIsSecondFactorConfirmed] = useState(false)

  const handleFailure = useCallback(
    (failure: unknown) => {
      if (!isLoginRestartFailure(failure)) return false
      onRestart(failure)
      return true
    },
    [onRestart],
  )

  if (!isSecondFactorConfirmed) {
    return (
      <SecondFactorStep
        flow={LOGIN_SETUP_FLOW}
        methods={methods}
        onConfirmed={() => setIsSecondFactorConfirmed(true)}
        onFailure={handleFailure}
      />
    )
  }
  return <RecoveryCodesStep flow={LOGIN_SETUP_FLOW} onFinish={completeLoginSetup} onFailure={handleFailure} />
}
