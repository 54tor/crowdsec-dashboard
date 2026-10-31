import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { ACCESS_RULES_QUERY_KEY, addAccessRule, type AccessRuleKind } from '@/api/accessRulesApi'
import { FormError } from '@/components/FormError'
import { LabelledInput } from '@/components/LabelledInput'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'

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
      <div className="space-y-2">
        <Label htmlFor="access-rule-kind">{t('accountSecurity.kindLabel')}</Label>
        <select
          id="access-rule-kind"
          value={kind}
          onChange={(changeEvent) => setKind(changeEvent.target.value as AccessRuleKind)}
          className="h-8 w-full rounded-lg border border-input bg-background px-2.5 text-sm"
        >
          <option value="ip">{t('accountSecurity.kinds.ip')}</option>
          <option value="country">{t('accountSecurity.kinds.country')}</option>
        </select>
      </div>
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
