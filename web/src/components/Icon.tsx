import { ICON_SOURCES, type IconName } from '@/components/iconSources'
import { cn } from '@/lib/utils'

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <span
      aria-hidden="true"
      data-icon={name}
      className={cn('inline-flex size-5 shrink-0 fill-current [&>svg]:size-full', className)}
      dangerouslySetInnerHTML={{ __html: ICON_SOURCES[name] }}
    />
  )
}
