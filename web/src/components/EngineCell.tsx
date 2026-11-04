import { UntrustedText } from '@/components/UntrustedText'
import { Badge } from '@/components/ui/badge'

export interface EngineCellProps {
  engineName: string
  badgeLabel?: string
  machineId?: string
}

export function EngineCell({ engineName, badgeLabel, machineId }: EngineCellProps) {
  return (
    <>
      <UntrustedText value={engineName} maxWidthClassName="max-w-[24ch]" />
      {badgeLabel && <Badge variant="outline" className="ml-2">{badgeLabel}</Badge>}
      {machineId && (
        <span className="block text-xs text-muted-foreground">
          <UntrustedText value={machineId} />
        </span>
      )}
    </>
  )
}
