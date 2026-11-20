import { Download, LogOut, RefreshCw, Users, Wallet } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import {
  AccountPresentation,
  IdentityCard,
  OrganizationsCard,
  SessionCard,
} from '../../components/auth/AccountPresentation'
import { Button } from '../../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card'
import { Controller, State } from './controller'
import { WalletPanel } from './WalletPanel'
import { RPCOnboarding } from './RPCOnboarding'

export function NativeAccountPage({
  controller,
  state,
  onSignOut,
  onSwitchAccount,
  onRefreshSession,
  onDownloadWalletToken,
  onCopyRPCCredential,
}: {
  controller: Controller
  state: State
  onSignOut?: () => void
  onSwitchAccount?: () => void
  onRefreshSession?: () => void
  onDownloadWalletToken?: () => void
  onCopyRPCCredential?: (format: 'token' | 'header' | 'foundry') => Promise<boolean>
}) {
  const navigate = useNavigate(),
    self = state.self!
  const provider = state.profiles.find((profile) => profile.id === self.sourceProfile)?.provider
  return (
    <AccountPresentation>
      <IdentityCard
        provider={
          provider === 'azure'
            ? 'Microsoft Entra ID'
            : provider === 'privado'
              ? 'Privado ID'
              : 'Verified OPS account'
        }
        identity={self.actorId}
        identityLabel="OPS identity"
      />
      <SessionCard
        expiresAt={self.expiresAt * 1000}
        note={
          provider === 'privado'
            ? 'Privado ID needs a fresh wallet proof when this identity is renewed.'
            : 'OPS checks with your identity provider when this session is renewed.'
        }
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              disabled={state.busy}
              onClick={() => (onRefreshSession ? onRefreshSession() : void controller.refresh())}
            >
              <RefreshCw className="h-4 w-4" />
              Refresh session
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              disabled={state.busy}
              onClick={() =>
                onSwitchAccount
                  ? onSwitchAccount()
                  : navigate('/login', { state: { switchAccount: true } })
              }
            >
              <Users className="h-4 w-4" />
              Switch account
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              disabled={state.busy}
              onClick={() => (onSignOut ? onSignOut() : void controller.logout())}
            >
              <LogOut className="h-4 w-4" />
              Sign Out
            </Button>
          </>
        }
      />
      <OrganizationsCard organizations={self.organizations} />
      <WalletPanel wallet={controller.wallet} sessionBusy={state.busy} />
      <RPCOnboarding key={`${self.actorId}:${self.expiresAt}:${self.sourceProfileDigest}`} controller={controller} onCopy={onCopyRPCCredential} organizations={self.organizations} busy={state.busy} expiresAt={self.expiresAt} />
      <Card data-testid="wallet-helper-handoff">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Wallet className="h-4 w-4 text-primary" />
            Browser wallet connection
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-neutral-600">
            To use your wallet in Explorer, run the local JWT helper with your own session token.
            OPS still checks every transaction against the approved permissions.
          </p>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            disabled={state.busy}
            onClick={() =>
              onDownloadWalletToken
                ? onDownloadWalletToken()
                : void controller.downloadOwnWalletToken()
            }
          >
            <Download className="h-4 w-4" />
            Download wallet token
          </Button>
          <p className="text-xs text-neutral-500">
            This file grants access as your identity until its original expiry. Keep it private.
            After refreshing your session, replace the helper’s token file and reconnect the wallet.
            Explorer provides the network settings.
          </p>
        </CardContent>
      </Card>
    </AccountPresentation>
  )
}
