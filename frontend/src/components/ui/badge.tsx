import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-all duration-200",
  {
    variants: {
      variant: {
        default: "border-neutral-200 bg-neutral-100 text-neutral-700",
        secondary: "border-neutral-200 bg-white text-neutral-500",
        destructive: "border-transparent bg-error-light text-error-dark",
        success: "border-transparent bg-success-light text-success-dark",
        warning: "border-transparent bg-warning-light text-warning-dark",
        info: "border-transparent bg-primary-50 text-primary",
        primary: "border-transparent bg-primary-50 text-primary",
        outline: "border-neutral-300 text-neutral-700 bg-transparent",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge }
