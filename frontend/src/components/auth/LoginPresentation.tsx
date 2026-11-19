import type { ReactNode } from 'react';
import { Shield, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { MicrosoftIcon, BillionsIcon, PrivadoIcon } from './ProviderIcons';

// Original LoginPage frame, shared without its legacy authentication runtime.
export function LoginFrame({ children }: { children: ReactNode }) {
  return <div className="flex min-h-screen items-center justify-center bg-neutral-100 p-4 overflow-x-hidden" data-testid="login-page">
    <div className="w-full max-w-md animate-fade-in-up">
      <div className="text-center mb-8" data-testid="login-header">
        <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-primary to-primary-300 shadow-lg shadow-primary"><Shield className="w-8 h-8 text-white" /></div>
        <h1 className="text-2xl font-bold text-neutral-900">Open Privacy Suite</h1>
        <p className="mt-1 text-neutral-500">Authenticated RPC Access</p>
      </div>
      {children}
    </div>
  </div>;
}

export function LoginCard({ title, description, tabs, children }: { title: string; description: ReactNode; tabs?: ReactNode; children: ReactNode }) {
  return <Card variant="default" data-testid="auth-card">
    <CardHeader className="text-center"><CardTitle data-testid="auth-title">{title}</CardTitle><CardDescription>{description}</CardDescription></CardHeader>
    {tabs}<CardContent>{children}</CardContent>
  </Card>;
}

export function LoginStatus({ tone, title, children }: { tone: 'loading' | 'success' | 'warning' | 'error'; title: string; children?: ReactNode }) {
  const Icon = tone === 'loading' ? Loader2 : tone === 'success' ? CheckCircle2 : AlertCircle;
  const colors = tone === 'success' ? 'bg-success-light text-success-dark' : tone === 'error' ? 'bg-error-light text-error-dark' : tone === 'warning' ? 'bg-warning-light text-warning-dark' : 'bg-primary-50 text-primary';
  return <div className="flex flex-col items-center gap-4 py-6" role={tone === 'error' ? 'alert' : 'status'}>
    <div className={`flex h-16 w-16 items-center justify-center rounded-full ${colors}`}><Icon className={`h-8 w-8 ${tone === 'loading' ? 'animate-spin' : ''}`} /></div>
    <div className="text-center"><p className="mb-2 font-medium text-neutral-900">{title}</p>{children && <div className="text-sm text-neutral-500">{children}</div>}</div>
  </div>;
}

export function MicrosoftLoginPanel({ children }: { children: ReactNode }) {
  return <div className="flex flex-col items-center gap-6 py-8" data-testid="azuread-section">
    <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[#0078d4]/10"><MicrosoftIcon className="h-8 w-8" /></div>
    <div className="text-center"><p className="font-medium text-neutral-900">Sign in with Microsoft</p><p className="mt-1 text-sm text-neutral-500">Use your @outlook.com, @hotmail.com, or corporate account</p></div>
    {children}
  </div>;
}

export function PrivadoBrandPanel({ billionsSupported = false }: { billionsSupported?: boolean }) {
  return <div className="flex flex-col items-center gap-3" data-testid="privado-brand-panel">
    <div className="flex items-center gap-3" aria-hidden="true">
      {billionsSupported && <><div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[#0046FF]/10" data-testid="brand-billions"><BillionsIcon className="h-6 w-auto" /></div><span className="text-neutral-300 text-sm">×</span></>}
      <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[#99FE5B]/30" data-testid="brand-privado"><PrivadoIcon className="h-7 w-7" /></div>
    </div>
    <p className="font-medium text-neutral-900">{billionsSupported ? 'Sign in with Billions/Privado' : 'Sign in with Privado ID'}</p>
  </div>;
}
