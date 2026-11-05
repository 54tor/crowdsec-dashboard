import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { validateMachine } from '@/api/writeApi'
import { ErrorNotice } from '@/components/Notice'
import { Button } from '@/components/ui/button'
import { ENGINE_WRITE_MUTATION_KEY } from '@/hooks/useEngineWritePending'
import { HEALTH_QUERY_KEY, MACHINES_QUERY_KEY } from '@/hooks/useReadResources'

interface MachineValidation {
  machineId: string
  engineName: string
}

export function ValidateMachineButton({ machineId, engineName }: { machineId: string; engineName: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const validation = useMutation({
    mutationKey: ENGINE_WRITE_MUTATION_KEY,
    mutationFn: (machineValidation: MachineValidation) => validateMachine(machineValidation.machineId, machineValidation.engineName),
    onSuccess: (_result, machineValidation) => {
      void queryClient.invalidateQueries({ queryKey: [...MACHINES_QUERY_KEY, machineValidation.engineName] })
      void queryClient.invalidateQueries({ queryKey: HEALTH_QUERY_KEY })
    },
  })
  return (
    <div className="space-y-1">
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-label={t('machines.validateAria', { name: machineId })}
        disabled={validation.isPending}
        onClick={() => validation.mutate({ machineId, engineName })}
      >
        {validation.isPending ? t('dialog.working') : t('machines.validate')}
      </Button>
      {validation.error && <ErrorNotice error={validation.error} />}
    </div>
  )
}
