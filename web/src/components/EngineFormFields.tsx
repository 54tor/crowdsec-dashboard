import { useTranslation } from 'react-i18next'
import { CheckboxField } from '@/components/CheckboxField'
import { EngineProxyFields } from '@/components/EngineProxyFields'
import { FormField } from '@/components/FormField'
import type { EngineFormValues, RequiredSecrets } from '@/lib/engineForm'

interface EngineFormFieldsProps {
  values: EngineFormValues
  required: RequiredSecrets
  isEditing: boolean
  onChange: (change: Partial<EngineFormValues>) => void
}

export function EngineFormFields({ values, required, isEditing, onChange }: EngineFormFieldsProps) {
  const { t } = useTranslation()
  const passwordHint = required.machinePassword
    ? isEditing
      ? t('engines.fields.machinePasswordRequired')
      : undefined
    : t('engines.fields.machinePasswordKeepHint')
  return (
    <div className="space-y-3">
      {!isEditing && (
        <FormField id="engine-name" label={t('engines.fields.name')} value={values.name} onChange={(changeEvent) => onChange({ name: changeEvent.target.value })} />
      )}
      <FormField id="engine-url" label={t('engines.fields.lapiUrl')} value={values.lapiUrl} onChange={(changeEvent) => onChange({ lapiUrl: changeEvent.target.value })} />
      <FormField id="engine-machine-id" label={t('engines.fields.machineId')} value={values.machineId} onChange={(changeEvent) => onChange({ machineId: changeEvent.target.value })} />
      <FormField
        id="engine-machine-password"
        label={t('engines.fields.machinePassword')}
        type="password"
        autoComplete="new-password"
        hint={isEditing ? passwordHint : undefined}
        value={values.machinePassword}
        onChange={(changeEvent) => onChange({ machinePassword: changeEvent.target.value })}
      />
      <EngineProxyFields values={values} required={required} isEditing={isEditing} onChange={onChange} />
      <FormField
        id="engine-public-addresses"
        label={t('engines.fields.publicAddresses')}
        hint={t('engines.fields.publicAddressesHint')}
        value={values.publicAddresses}
        onChange={(changeEvent) => onChange({ publicAddresses: changeEvent.target.value })}
      />
      <CheckboxField id="engine-insecure" label={t('engines.fields.allowInsecureHttp')} checked={values.allowInsecureHttp} onChange={(isChecked) => onChange({ allowInsecureHttp: isChecked })} />
      <CheckboxField id="engine-enabled" label={t('engines.fields.enabled')} checked={values.enabled} onChange={(isChecked) => onChange({ enabled: isChecked })} />
      <CheckboxField id="engine-sync" label={t('engines.fields.syncEnabled')} checked={values.syncEnabled} onChange={(isChecked) => onChange({ syncEnabled: isChecked })} />
    </div>
  )
}
