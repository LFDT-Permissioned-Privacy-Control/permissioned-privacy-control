import { AlertTriangle, Info, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void | Promise<void>;
  variant?: 'default' | 'destructive' | 'warning';
  isLoading?: boolean;
}

const iconMap = {
  default: Info,
  destructive: AlertCircle,
  warning: AlertTriangle,
};

const iconColorMap = {
  default: 'text-primary',
  destructive: 'text-error-dark',
  warning: 'text-warning-dark',
};

const buttonVariantMap = {
  default: 'default' as const,
  destructive: 'destructive' as const,
  warning: 'default' as const,
};

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  onConfirm,
  variant = 'default',
  isLoading = false,
}: ConfirmDialogProps) {
  const Icon = iconMap[variant];
  const iconColor = iconColorMap[variant];
  const buttonVariant = buttonVariantMap[variant];

  const handleConfirm = async () => {
    await onConfirm();
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icon className={`w-5 h-5 ${iconColor}`} />
            {title}
          </DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isLoading}
          >
            {cancelLabel}
          </Button>
          <Button
            variant={buttonVariant}
            onClick={handleConfirm}
            disabled={isLoading}
          >
            {isLoading ? 'Loading...' : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export interface AlertDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  buttonLabel?: string;
  variant?: 'default' | 'error' | 'warning' | 'success';
}

const alertIconMap = {
  default: Info,
  error: AlertCircle,
  warning: AlertTriangle,
  success: Info,
};

const alertIconColorMap = {
  default: 'text-primary',
  error: 'text-error-dark',
  warning: 'text-warning-dark',
  success: 'text-success-dark',
};

const alertButtonVariantMap = {
  default: 'default' as const,
  error: 'destructive' as const,
  warning: 'default' as const,
  success: 'success' as const,
};

export function AlertDialog({
  open,
  onOpenChange,
  title,
  description,
  buttonLabel = 'OK',
  variant = 'default',
}: AlertDialogProps) {
  const Icon = alertIconMap[variant];
  const iconColor = alertIconColorMap[variant];
  const buttonVariant = alertButtonVariantMap[variant];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icon className={`w-5 h-5 ${iconColor}`} />
            {title}
          </DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <DialogFooter>
          <Button variant={buttonVariant} onClick={() => onOpenChange(false)}>
            {buttonLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default ConfirmDialog;
