import { cn } from '@/lib/utils'

interface UntrustedTextProps {
  value: string
  maxWidthClassName?: string
}

export function UntrustedText({ value, maxWidthClassName }: UntrustedTextProps) {
  if (maxWidthClassName === undefined) {
    return <bdi className="whitespace-pre-wrap [overflow-wrap:anywhere]">{value}</bdi>
  }
  return (
    <bdi data-truncated="" title={value} className={cn('inline-block truncate align-bottom', maxWidthClassName)}>
      {value}
    </bdi>
  )
}
