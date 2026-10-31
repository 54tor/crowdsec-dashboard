import { useState } from 'react'
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

  async function finishSetup() {
    try {
      await completeLoginSetup()
    } catch (completeFailure) {
      if (isLoginRestartFailure(completeFailure)) {
        onRestart(completeFailure)
        return
      }
      throw completeFailure
    }
  }

  if (!isSecondFactorConfirmed) {
    return <SecondFactorStep flow={LOGIN_SETUP_FLOW} methods={methods} onConfirmed={() => setIsSecondFactorConfirmed(true)} />
  }
  return <RecoveryCodesStep flow={LOGIN_SETUP_FLOW} onFinish={finishSetup} />
}
