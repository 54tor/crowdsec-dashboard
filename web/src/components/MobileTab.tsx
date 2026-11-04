import { Icon } from '@/components/Icon'
import type { IconName } from '@/components/iconSources'

export const MOBILE_TAB_CLASS_NAME =
  'group grid min-h-11 content-center justify-items-center gap-0.5 rounded-md font-condensed text-[11px] font-semibold tracking-wide text-muted-foreground focus-ring aria-[current=page]:text-foreground'

export function MobileTabContent({ icon, label }: { icon: IconName; label: string }) {
  return (
    <>
      <span className="grid h-7 w-13 place-items-center rounded-full group-aria-[current=page]:bg-primary group-aria-[current=page]:text-primary-foreground group-data-[state=open]:bg-secondary">
        <Icon name={icon} className="size-5" />
      </span>
      {label}
    </>
  )
}
