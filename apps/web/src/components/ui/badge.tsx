import * as React from "react"

import { cn } from "@/lib/utils"

const Badge = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & {
    variant?: "default" | "secondary" | "destructive" | "outline"
  }
>(({ className, variant = "default", ...props }, ref) => {
  const variantStyles = {
    default: "bg-primary text-primary-foreground border-border shadow-sm",
    secondary: "bg-secondary text-secondary-foreground border-border shadow-sm",
    destructive: "bg-destructive text-destructive-foreground border-border shadow-sm",
    outline: "border-input bg-background border-border",
  }

  return (
    <div
      ref={ref}
      className={cn(
        "inline-flex items-center border-2 px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
        variantStyles[variant],
        className
      )}
      {...props}
    />
  )
})
Badge.displayName = "Badge"

export { Badge }
