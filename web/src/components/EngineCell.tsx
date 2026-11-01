import { UntrustedText } from '@/components/UntrustedText'
import { Badge } from '@/components/ui/badge'

interface EngineCellProps {
  engineName: string
  badgeLabel?: string
}

export function EngineCell({ engineName, badgeLabel }: EngineCellProps) {
  return (
    <>
      <UntrustedText value={engineName} />
      {badgeLabel && <Badge variant="outline" className="ml-2">{badgeLabel}</Badge>}
    </>
  )
}
