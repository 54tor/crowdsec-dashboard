import { useEffect, useRef } from 'react'

export function StepHeading({ title, description }: { title: string; description: string }) {
  const headingReference = useRef<HTMLHeadingElement>(null)

  useEffect(() => {
    headingReference.current?.focus()
  }, [])

  return (
    <div className="space-y-1">
      <h2 ref={headingReference} tabIndex={-1} className="text-base font-medium outline-none">
        {title}
      </h2>
      <p className="text-sm text-muted-foreground">{description}</p>
    </div>
  )
}
