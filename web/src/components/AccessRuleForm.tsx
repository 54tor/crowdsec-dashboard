import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { ACCESS_RULES_QUERY_KEY, addAccessRule, type AccessRuleKind } from '@/api/accessRulesApi'
import { FormError } from '@/components/FormError'
import { LabelledInput } from '@/components/LabelledInput'
import { SelectField } from '@/components/SelectField'
import { Button } from '@/components/ui/button'

export function AccessRuleForm() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const valueInput = useRef<HTMLInputElement>(null)
  const [kind, setKind] = useState<AccessRuleKind>('ip')
  const [value, setValue] = useState('')
  const creation = useMutation({
    mutationFn: () => addAccessRule(kind, kind === 'country' ? value.trim().toUpperCase() : value.trim()),
    onSuccess: () => {
      setValue('')
      valueInput.current?.focus()
      void queryClient.invalidateQueries({ queryKey: ACCESS_RULES_QUERY_KEY })
    },
  })

  function submit(submitEvent: FormEvent) {
    submitEvent.preventDefault()
    if (!creation.isPending) {
      creation.mutate()
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3" aria-label={t('accountSecurity.addTitle')}>
      <h2 className="text-lg font-medium">{t('accountSecurity.addTitle')}</h2>
      <SelectField
        id="access-rule-kind"
        label={t('accountSecurity.kindLabel')}
        value={kind}
        options={[
          { value: 'ip', label: t('accountSecurity.kinds.ip') },
          { value: 'country', label: t('accountSecurity.kinds.country') },
        ]}
        onChange={(chosenKind) => setKind(chosenKind as AccessRuleKind)}
      />
      <LabelledInput
        ref={valueInput}
        id="access-rule-value"
        label={t('accountSecurity.valueLabel')}
        value={value}
        onChange={(changeEvent) => setValue(changeEvent.target.value)}
        placeholder={kind === 'country' ? 'FR' : '203.0.113.0/24'}
        autoComplete="off"
        spellCheck={false}
        maxLength={64}
      />
      {creation.isError && <FormError key={creation.submittedAt} failure={creation.error} />}
      <Button type="submit" disabled={creation.isPending}>
        {creation.isPending ? t('dialog.working') : t('accountSecurity.add')}
      </Button>
    </form>
  )
}
