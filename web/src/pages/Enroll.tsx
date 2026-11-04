import { useMemo, useState, type ComponentType } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router'
import { AuthPageShell } from '@/components/AuthPageShell'
import { EnrollAccountStep, type EnrollStepProps, type EnrollmentProgress } from '@/components/EnrollAccountStep'
import { RecoveryCodesStep } from '@/components/RecoveryCodesStep'
import { SecondFactorStep } from '@/components/SecondFactorStep'
import { useAuth } from '@/auth/useAuth'
import { useEnrollmentStatus } from '@/auth/useEnrollmentStatus'
import type { SecondFactorFlow } from '@/api/secondFactorApi'

interface EnrollStep {
  id: string
  Component: ComponentType<EnrollStepProps>
}

function useEnrollmentFlow(token: string): SecondFactorFlow {
  return useMemo(() => ({ basePath: '/api/auth/enroll', extraBody: { token } }), [token])
}

function EnrollSecondFactorStep({ progress, onComplete }: EnrollStepProps) {
  const flow = useEnrollmentFlow(progress.token)
  return <SecondFactorStep flow={flow} methods={progress.methods} onConfirmed={() => onComplete()} />
}

function EnrollRecoveryCodesStep({ progress }: EnrollStepProps) {
  const { completeEnrollment } = useAuth()
  const flow = useEnrollmentFlow(progress.token)
  return <RecoveryCodesStep flow={flow} onFinish={() => completeEnrollment(progress.token)} />
}

const ENROLL_STEPS: EnrollStep[] = [
  { id: 'account', Component: EnrollAccountStep },
  { id: 'secondFactor', Component: EnrollSecondFactorStep },
  { id: 'recoveryCodes', Component: EnrollRecoveryCodesStep },
]

const EMPTY_PROGRESS: EnrollmentProgress = { token: '', methods: [] }

export function Enroll() {
  const { t } = useTranslation()
  const { isAuthenticated } = useAuth()
  const { isPending: isStatusPending, isEnrollmentRequired } = useEnrollmentStatus()
  const [currentStepIndex, setCurrentStepIndex] = useState(0)
  const [progress, setProgress] = useState<EnrollmentProgress>(EMPTY_PROGRESS)

  if (isAuthenticated) {
    return <Navigate to="/alerts" replace />
  }
  if (isStatusPending) {
    return <AuthPageShell title={t('enroll.title')} description={t('enroll.description')} isLoading />
  }
  if (!isEnrollmentRequired) {
    return <Navigate to="/login" replace />
  }

  const { Component: CurrentStep } = ENROLL_STEPS[currentStepIndex]

  function goToNextStep(nextProgress?: EnrollmentProgress) {
    if (nextProgress) {
      setProgress(nextProgress)
    }
    setCurrentStepIndex((previousStepIndex) => Math.min(previousStepIndex + 1, ENROLL_STEPS.length - 1))
  }

  return (
    <AuthPageShell title={t('enroll.title')} description={t('enroll.description')}>
      <CurrentStep progress={progress} onComplete={goToNextStep} />
    </AuthPageShell>
  )
}
