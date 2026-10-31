import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { validateMachine } from '@/api/writeApi'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { HEALTH_QUERY_KEY } from '@/hooks/useReadResources'

export function ValidateMachineButton({ machineId }: { machineId: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const validation = useMutation({
    mutationFn: () => validateMachine(machineId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: HEALTH_QUERY_KEY }),
  })
  return (
    <div className="space-y-1">
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-label={t('machines.validateAria', { name: machineId })}
        disabled={validation.isPending}
        onClick={() => validation.mutate()}
      >
        {validation.isPending ? t('dialog.working') : t('machines.validate')}
      </Button>
      {validation.error && <ErrorNotice error={validation.error} />}
    </div>
  )
}
