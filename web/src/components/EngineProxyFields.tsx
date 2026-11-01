import { useTranslation } from 'react-i18next'
import { CheckboxField } from '@/components/CheckboxField'
import { FormField } from '@/components/FormField'
import { Label } from '@/components/ui/label'
import type { EngineFormValues, ProxyKindChoice, RequiredSecrets } from '@/lib/engineForm'

interface EngineProxyFieldsProps {
  values: EngineFormValues
  required: RequiredSecrets
  isEditing: boolean
  onChange: (change: Partial<EngineFormValues>) => void
}

export function EngineProxyFields({ values, required, isEditing, onChange }: EngineProxyFieldsProps) {
  const { t } = useTranslation()
  const hasProxy = values.proxyKind !== ''
  const credentialsHint = required.proxyCredentials ? t('engines.fields.proxyCredentialsRequired') : t('engines.fields.proxyCredentialsHint')
  return (
    <div className="space-y-3">
      <div className="space-y-1">
        <Label htmlFor="engine-proxy-kind">{t('engines.fields.proxyKind')}</Label>
        <select
          id="engine-proxy-kind"
          value={values.proxyKind}
          onChange={(changeEvent) => onChange({ proxyKind: changeEvent.target.value as ProxyKindChoice })}
          className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-sm"
        >
          <option value="">{t('engines.fields.proxyNone')}</option>
          <option value="socks5">socks5</option>
          <option value="http">http</option>
        </select>
      </div>
      {hasProxy && (
        <>
          <FormField id="engine-proxy-url" label={t('engines.fields.proxyUrl')} value={values.proxyUrl} onChange={(changeEvent) => onChange({ proxyUrl: changeEvent.target.value })} />
          <FormField
            id="engine-proxy-username"
            label={t('engines.fields.proxyUsername')}
            autoComplete="new-password"
            value={values.proxyUsername}
            onChange={(changeEvent) => onChange({ proxyUsername: changeEvent.target.value })}
          />
          <FormField
            id="engine-proxy-password"
            label={t('engines.fields.proxyPassword')}
            type="password"
            autoComplete="new-password"
            hint={credentialsHint}
            value={values.proxyPassword}
            onChange={(changeEvent) => onChange({ proxyPassword: changeEvent.target.value })}
          />
          {isEditing && (
            <CheckboxField
              id="engine-proxy-clear"
              label={t('engines.fields.clearProxyCredentials')}
              checked={values.clearProxyCredentials}
              onChange={(isChecked) => onChange({ clearProxyCredentials: isChecked })}
            />
          )}
        </>
      )}
    </div>
  )
}
