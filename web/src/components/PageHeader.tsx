import type { ReactNode, Ref } from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  actions?: ReactNode
  titleRef?: Ref<HTMLHeadingElement>
}

export function PageHeader({ title, description, actions, titleRef }: PageHeaderProps) {
  const isTitleFocusTarget = titleRef !== undefined
  return (
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0 space-y-1">
        <h1
          ref={titleRef}
          tabIndex={isTitleFocusTarget ? -1 : undefined}
          className="font-condensed text-2xl font-semibold tracking-tight outline-none"
        >
          {title}
        </h1>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}
