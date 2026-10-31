import { useState, type ComponentType } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router'
import { AuthPageShell } from '@/components/AuthPageShell'
import { EnrollAccountStep, type EnrollStepProps } from '@/components/EnrollAccountStep'
import { useAuth } from '@/auth/useAuth'
import { useEnrollmentStatus } from '@/auth/useEnrollmentStatus'

interface EnrollStep {
  id: string
  Component: ComponentType<EnrollStepProps>
}

const ENROLL_STEPS: EnrollStep[] = [{ id: 'account', Component: EnrollAccountStep }]

export function Enroll() {
  const { t } = useTranslation()
  const { isAuthenticated } = useAuth()
  const { isPending: isStatusPending, isEnrollmentRequired } = useEnrollmentStatus()
  const [currentStepIndex, setCurrentStepIndex] = useState(0)

  if (isAuthenticated) {
    return <Navigate to="/alerts" replace />
  }
  if (isStatusPending) {
    return <p className="p-6 text-sm text-muted-foreground">{t('common.loading')}</p>
  }
  if (!isEnrollmentRequired) {
    return <Navigate to="/login" replace />
  }

  const { Component: CurrentStep } = ENROLL_STEPS[currentStepIndex]

  function goToNextStep() {
    setCurrentStepIndex((previousStepIndex) => Math.min(previousStepIndex + 1, ENROLL_STEPS.length - 1))
  }

  return (
    <AuthPageShell title={t('enroll.title')} description={t('enroll.description')}>
      <CurrentStep onComplete={goToNextStep} />
    </AuthPageShell>
  )
}
