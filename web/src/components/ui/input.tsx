import * as React from "react"
import { cn } from "cn"
import { FIELD_CONTROL_CLASS_NAME } from "@/components/ui/fieldControl"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        FIELD_CONTROL_CLASS_NAME,
        "py-1 file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-muted-foreground",
        className
      )}
      {...props}
    />
  )
}

export { Input }
