import { useTranslation } from 'react-i18next'
import { SecretReveal } from '@/components/SecretReveal'

interface SidecarKeyLinesProps {
  trustedKeyLine: string
  issuer?: string
  audience?: string
}

interface SidecarSetting {
  label: string
  value: string
}

function sidecarSettings(trustedKeyLine: string, issuer: string | undefined, audience: string | undefined, labels: { trustedKey: string; issuer: string; audience: string }): SidecarSetting[] {
  const settings: SidecarSetting[] = [{ label: labels.trustedKey, value: trustedKeyLine }]
  if (issuer !== undefined) {
    settings.push({ label: labels.issuer, value: `SIDECAR_ISSUER=${issuer}` })
  }
  if (audience !== undefined) {
    settings.push({ label: labels.audience, value: `SIDECAR_AUDIENCE=${audience}` })
  }
  return settings
}

export function SidecarKeyLines({ trustedKeyLine, issuer, audience }: SidecarKeyLinesProps) {
  const { t } = useTranslation()
  const settings = sidecarSettings(trustedKeyLine, issuer, audience, {
    trustedKey: t('engines.sidecar.trustedKeyLine'),
    issuer: t('engines.sidecar.issuerLine'),
    audience: t('engines.sidecar.audienceLine'),
  })
  return (
    <div className="space-y-3">
      {settings.map((setting) => (
        <SecretReveal key={setting.label} label={setting.label} secret={setting.value} copyAriaLabel={t('engines.sidecar.copyAria', { label: setting.label })} />
      ))}
    </div>
  )
}
