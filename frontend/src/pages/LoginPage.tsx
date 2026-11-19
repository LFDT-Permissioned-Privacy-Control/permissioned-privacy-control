import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { QRCodeSVG } from 'qrcode.react';
import { ExternalLink, Loader2, AlertCircle, CheckCircle2, FlaskConical } from 'lucide-react';
import { DevelopmentIdentityPicker } from '../components/auth/DevelopmentIdentityPicker';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { MicrosoftIcon, BillionsIcon, PrivadoIcon } from '@/components/auth/ProviderIcons';
import { LoginFrame, MicrosoftLoginPanel, PrivadoBrandPanel } from '@/components/auth/LoginPresentation';
import { useAuth } from '@/contexts/AuthContext';
import { authApiMethods, generatePrivadoLink, isMobileDevice, AuthRequestResponse, HumanityVerificationError } from '@/api/auth';

// Mock login requires explicit opt-in via VITE_ALLOW_MOCK_LOGIN=true
const allowMockLogin = import.meta.env.VITE_ALLOW_MOCK_LOGIN === 'true';

interface TestIdentity {
  did: string;
  name: string;
  note?: string;
  addresses: string[];
  orgs: string[];
}

const AUTH_POLL_INTERVAL_MS = 2000;
const AUTH_MAX_POLLS = 150;

// Fallback for the humanity flow when the reason arrives via the polled session
// rather than the wallet's own 403 (which carries a verify_url).
const BILLIONS_VERIFY_URL = 'https://app.billions.network';

type AuthStep = 'init' | 'loading' | 'ready' | 'success' | 'error' | 'humanity_required' | 'timed_out';
type AuthProvider = 'privado' | 'azuread';

interface AuthState {
  step: AuthStep;
  sessionId: string | null;
  authRequest: AuthRequestResponse['auth_request'] | null;
  error: string | null;
  humanityVerifyUrl: string | null;
  oauthRedirectUrl: string | null;
  // RD-1242: a rejected proof, surfaced WITHOUT leaving the 'ready' step so the
  // poll loop stays alive. The backend treats a failure as non-terminal (a
  // wallet retry can still complete), and the session ID is visible in the QR
  // code, so anyone who photographs it can post one bogus token. Tearing the
  // page down here would let that cancel a legitimate login.
  failureReason: string | null;
}

// Maps a curated failure code from the polled session (RD-1242) to the step and
// copy the user sees. The codes come from the backend's closed allowlist, so an
// unrecognised value here means a newer backend: fall back to the generic
// message rather than rendering the raw code.
function authFailureMessage(reason: string): string {
  switch (reason) {
    case 'verification_failed':
      return 'Your wallet’s proof could not be verified. Generate a new QR code and try again, or contact your administrator if this keeps happening.';
    case 'invalid_request':
      return 'Your wallet sent a response the server could not read. Generate a new QR code and try again.';
    case 'network_not_supported':
      // RD-1251. Neither the user's fault nor fixable by retrying: this
      // deployment has no state resolver for the wallet's identity network, so
      // say so plainly instead of inviting another scan that fails identically.
      return 'This deployment does not support your wallet’s identity network, so its proof cannot be verified here. Retrying will not help — ask your administrator to enable that network, or sign in with a wallet on a supported one.';
    default:
      return 'Authentication failed. Generate a new QR code and try again, or contact your administrator.';
  }
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, isAuthenticated, isLoading, userDID } = useAuth();
  const from = (location.state as { from?: string } | null)?.from || '/link-wallet';
  // OAuth mode: the block-explorer redirected here via /oauth/authorize -> /login?oauth_session=XXX.
  // Read from the router location (not module-scope window.location) so it is reactive and testable.
  const oauthSessionId = useMemo(
    () => new URLSearchParams(location.search).get('oauth_session'),
    [location.search]
  );
  const isOAuthMode = !!oauthSessionId;
  const [testIdentities, setTestIdentities] = useState<TestIdentity[]>([]);
  const [providers, setProviders] = useState<string[]>(['privado']);
  // iden3 networks this deployment can actually verify (RD-1241). Starts empty
  // and stays empty if the probe fails or the backend omits the field: the
  // brand panel must not promise a network we have not confirmed.
  const [networks, setNetworks] = useState<string[]>([]);
  // Derived here, immediately below the state it reads, so it cannot be
  // referenced before `networks` exists.
  const billionsSupported = networks.includes('billions:main');
  const [activeProvider, setActiveProvider] = useState<AuthProvider>('privado');
  const [azureLoading, setAzureLoading] = useState(false);
  const [state, setState] = useState<AuthState>({
    step: 'init',
    sessionId: null,
    authRequest: null,
    error: null,
    humanityVerifyUrl: null,
    oauthRedirectUrl: null,
    failureReason: null,
  });

  // Redirect if already authenticated (skip in OAuth mode — user is authenticating for a third-party app)
  useEffect(() => {
    if (!isOAuthMode && isAuthenticated) {
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, isLoading, from, isOAuthMode]);

  // Load available providers (silently ignore errors — default to privado only)
  useEffect(() => {
    authApiMethods
      .getAuthProviders()
      .then((res) => {
        setProviders(res.providers);
        setNetworks(res.networks ?? []);
      })
      .catch(() => {});
  }, []);

  // Fetch test identities for dev identity picker (only in mock login mode)
  useEffect(() => {
    if (!allowMockLogin) return;
    fetch('/api/v1/dev/test-identities')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data?.identities) setTestIdentities(data.identities);
      })
      .catch(() => {}); // silently ignore — endpoint may not exist
  }, []);

  // Handle "Sign in with Microsoft" — fetch auth URL then redirect browser
  const handleAzureLogin = useCallback(async () => {
    setAzureLoading(true);
    try {
      // Persist the return-to path so the callback page can restore it
      // after the full-page redirect through Microsoft.
      sessionStorage.setItem('azure_login_from', from);
      const redirectURI = `${window.location.origin}/auth/azure/callback`;
      const { url } = await authApiMethods.getAzureAuthURL(redirectURI);
      window.location.href = url;
    } catch {
      setAzureLoading(false);
    }
  }, [from]);

  // Start auth request
  const startAuth = useCallback(async () => {
    setState(prev => ({ ...prev, step: 'loading', error: null }));

    try {
      const response = await authApiMethods.requestAuth();
      setState({
        step: 'ready',
        sessionId: response.session_id,
        authRequest: response.auth_request,
        error: null,
        humanityVerifyUrl: null,
        oauthRedirectUrl: null,
        failureReason: null,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to start authentication';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    }
  }, []);

  // Start OAuth auth: fetch session info from backend instead of creating a new session
  const startOAuthAuth = useCallback(async () => {
    if (!oauthSessionId) return;
    setState(prev => ({ ...prev, step: 'loading', error: null }));
    try {
      const res = await fetch(`/oauth/session/${oauthSessionId}/info`);
      if (!res.ok) throw new Error('Failed to load session');
      const data = await res.json();
      setState({
        step: 'ready',
        sessionId: oauthSessionId,
        authRequest: data.auth_request,
        error: null,
        humanityVerifyUrl: null,
        oauthRedirectUrl: null,
        failureReason: null,
      });
    } catch {
      setState(prev => ({ ...prev, step: 'error', error: 'Failed to load authentication session' }));
    }
  }, [oauthSessionId]);

  // Mock login for development (requires explicit opt-in)
  const handleMockLogin = useCallback(async () => {
    if (!allowMockLogin) return;

    setState(prev => ({ ...prev, step: 'loading', error: null }));

    try {
      if (isOAuthMode && oauthSessionId) {
        // OAuth mode: complete the session, fetch redirect URL, then navigate.
        // If the user already has an active PP session (first-party SSO into
        // block-explorer), reuse their DID rather than minting a fresh
        // mock_<timestamp> identity — otherwise the OAuth callback hands BE
        // a different user than the admin currently sees on the PP dashboard.
        const completeBody = userDID ? JSON.stringify({ did: userDID }) : undefined;
        const res = await fetch(`/oauth/session/${oauthSessionId}/mock-complete`, {
          method: 'POST',
          headers: completeBody ? { 'Content-Type': 'application/json' } : undefined,
          body: completeBody,
        });
        const data = await res.json();
        if (!data.ok) {
          throw new Error(data.error || 'Mock login failed');
        }
        const statusRes = await fetch(`/oauth/session/${oauthSessionId}/status`);
        const statusData = await statusRes.json();
        if (!statusData.completed || !statusData.redirect_url) {
          throw new Error('Session did not complete');
        }
        setState(prev => ({ ...prev, step: 'success' }));
        setTimeout(() => { window.location.href = statusData.redirect_url; }, 1000);
      } else {
        // Normal mode: request auth, verify with mock token, login
        const authResponse = await authApiMethods.requestAuth();

        // Reuse the same dev DID across sessions so ETH address links persist
        const MOCK_DID_KEY = 'privacy-proxy-mock-did';
        let mockDID = localStorage.getItem(MOCK_DID_KEY);
        if (!mockDID) {
          mockDID = `did:privado:dev_${Date.now()}`;
          localStorage.setItem(MOCK_DID_KEY, mockDID);
        }
        const tokens = await authApiMethods.verifyAuth(authResponse.session_id, `mock.${mockDID}`);

        login(tokens.access_token, tokens.refresh_token, tokens.expires_in);
        setState(prev => ({ ...prev, step: 'success' }));
        setTimeout(() => navigate(from, { replace: true }), 1000);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Mock login failed';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    }
  }, [login, navigate, from, userDID, isOAuthMode, oauthSessionId]);

  // Mock login as a specific test identity (dev identity picker)
  const handleMockLoginAs = useCallback(async (did: string) => {
    if (!allowMockLogin) return;

    setState(prev => ({ ...prev, step: 'loading', error: null }));

    try {
      if (isOAuthMode && oauthSessionId) {
        // OAuth mode: complete the session with specific DID
        const res = await fetch(`/oauth/session/${oauthSessionId}/mock-complete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ did }),
        });
        const data = await res.json();
        if (!data.ok) {
          throw new Error(data.error || 'Mock login failed');
        }
        const statusRes = await fetch(`/oauth/session/${oauthSessionId}/status`);
        const statusData = await statusRes.json();
        if (!statusData.completed || !statusData.redirect_url) {
          throw new Error('Session did not complete');
        }
        setState(prev => ({ ...prev, step: 'success' }));
        setTimeout(() => { window.location.href = statusData.redirect_url; }, 1000);
      } else {
        // Normal mode: request auth, verify with specific DID
        const authResponse = await authApiMethods.requestAuth();
        const tokens = await authApiMethods.verifyAuth(authResponse.session_id, `mock.${did}`);
        login(tokens.access_token, tokens.refresh_token, tokens.expires_in);
        setState(prev => ({ ...prev, step: 'success' }));
        setTimeout(() => navigate(from, { replace: true }), 1000);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Mock login failed';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    }
  }, [login, navigate, from, isOAuthMode, oauthSessionId]);

  // First-party silent SSO. When the OAuth flow lands here, ask the backend to
  // silent-complete (auth code issued without showing the QR / mock-login
  // picker). This is attempted even when this tab holds no session in
  // sessionStorage: silent-complete authenticates via the access-token cookie,
  // which rides along on this same-origin request. The backend gates on:
  //   - the cookie's DID matching the OAuth session's initiator DID
  //     (defends against pre-created session-id lures)
  //   - the session's client on the first-party allowlist
  // On 4xx (any precondition fails) the function returns false and we fall
  // through to the next branch — dev-mock auto-complete, or the interactive
  // picker.
  const trySilentSSO = useCallback(async (): Promise<boolean> => {
    if (!isOAuthMode || !oauthSessionId) {
      return false;
    }
    setState(prev => ({ ...prev, step: 'loading', error: null }));
    try {
      // Cookie-only: no Authorization header. The middleware prefers a Bearer
      // header over the cookie, so sending a possibly-stale in-tab token could
      // authenticate as a different DID than the cookie the initiator was
      // recorded from, breaking the initiator-match check. The cookie is the
      // authoritative source here.
      const res = await fetch(`/oauth/session/${oauthSessionId}/silent-complete`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!res.ok) {
        // 401 / 403 / 404 / 409: ineligible for silent SSO. Reset state.step
        // so the caller can drop into the next branch instead of leaving us
        // stuck on 'loading'.
        setState(prev => ({ ...prev, step: 'init', error: null }));
        return false;
      }
      const data = await res.json();
      if (!data.completed || !data.redirect_url) {
        setState(prev => ({ ...prev, step: 'init', error: null }));
        return false;
      }
      setState(prev => ({ ...prev, step: 'success' }));
      window.location.href = data.redirect_url;
      return true;
    } catch {
      setState(prev => ({ ...prev, step: 'init', error: null }));
      return false;
    }
  }, [isOAuthMode, oauthSessionId]);

  // Wait on isLoading so AuthProvider has restored any sessionStorage session
  // before we read isAuthenticated below. autoStartedFor makes auto-start a
  // one-shot: trySilentSSO resets state.step to 'init' on refusal, and without
  // this guard the effect would re-enter and race its own fall-through
  // (startOAuthAuth / handleMockLogin). The login target (oauth_session id, or
  // 'plain') only ever arrives via a full-page redirect from the block-explorer
  // (/oauth/authorize -> /login?oauth_session=…), so each target is a fresh
  // mount; keying the guard on the target rather than a bare boolean just keeps
  // it correct if that ever stops holding. Explicit "Try again" goes through
  // startAuth directly.
  const autoStartedFor = useRef<string | null>(null);
  useEffect(() => {
    if (isLoading) return;
    if (state.step !== 'init') return;
    const startKey = oauthSessionId ?? 'plain';
    if (autoStartedFor.current === startKey) return;
    autoStartedFor.current = startKey;

    if (isOAuthMode) {
      // Cookie-based silent SSO first (works cross-tab). On refusal: reuse the
      // current DID if this tab is authenticated + mock enabled, else show the
      // interactive picker — never silently mint a random DID.
      void trySilentSSO().then(success => {
        if (success) return;
        if (isAuthenticated && allowMockLogin && oauthSessionId) {
          handleMockLogin();
          return;
        }
        startOAuthAuth();
      });
      return;
    }

    startAuth();
  }, [
    state.step,
    isLoading,
    isAuthenticated,
    isOAuthMode,
    oauthSessionId,
    trySilentSSO,
    handleMockLogin,
    startAuth,
    startOAuthAuth,
  ]);

  // Poll for session completion
  useEffect(() => {
    if (state.step !== 'ready' || !state.sessionId) return;

    let mounted = true;
    let pollCount = 0;

    const poll = async () => {
      if (!mounted) return;
      if (pollCount >= AUTH_MAX_POLLS) {
        setState(prev => ({
          ...prev,
          step: 'timed_out',
          error: 'Authentication timed out. Generate a new QR code and try again.',
        }));
        return;
      }

      try {
        if (isOAuthMode && oauthSessionId) {
          // OAuth mode: poll the OAuth session status endpoint
          const res = await fetch(`/oauth/session/${oauthSessionId}/status`);
          if (res.ok) {
            const data = await res.json();
            if (data.completed && data.redirect_url && mounted) {
              setState(prev => ({ ...prev, step: 'success', oauthRedirectUrl: data.redirect_url }));
              // Redirect back to the calling application after a brief delay
              setTimeout(() => {
                window.location.href = data.redirect_url;
              }, 1000);
              return;
            }
          }
        } else {
          // Normal mode: poll auth session for JWT tokens
          const result = await authApiMethods.pollSession(state.sessionId!);
          if (result && mounted) {
            if (result.status === 'failed') {
              // RD-1242: report the rejection, but keep polling. A missing
              // humanity credential needs the user to act, so that one becomes
              // its own step; every other rejection is shown in place so a
              // wallet retry (or a bogus callback from someone who photographed
              // the QR) cannot cancel a login that later succeeds.
              if (result.reason === 'humanity_required') {
                setState(prev => ({
                  ...prev,
                  step: 'humanity_required',
                  humanityVerifyUrl: BILLIONS_VERIFY_URL,
                }));
                return;
              }
              // Identical reason => return prev so the state object is stable
              // and this effect is not torn down and restarted every 2s.
              setState(prev =>
                prev.failureReason === result.reason
                  ? prev
                  : { ...prev, failureReason: result.reason }
              );
            } else {
              login(result.tokens.access_token, result.tokens.refresh_token, result.tokens.expires_in);
              setState(prev => ({ ...prev, step: 'success' }));
              setTimeout(() => navigate(from, { replace: true }), 1000);
              return;
            }
          }
        }
      } catch (err) {
        // Check for humanity verification error
        const errorData = err as { response?: { data?: HumanityVerificationError } };
        if (errorData?.response?.data?.error === 'humanity_verification_required') {
          setState(prev => ({
            ...prev,
            step: 'humanity_required',
            humanityVerifyUrl: errorData.response!.data!.verify_url,
          }));
          return;
        }
        // Otherwise continue polling
      }

      pollCount++;
      if (mounted) {
        setTimeout(poll, AUTH_POLL_INTERVAL_MS);
      }
    };

    // Start polling after a short delay
    const timer = setTimeout(poll, AUTH_POLL_INTERVAL_MS);
    return () => {
      mounted = false;
      clearTimeout(timer);
    };
  }, [state.step, state.sessionId, login, navigate, from, isOAuthMode, oauthSessionId]);

  // Handle mobile deep link
  const handleMobileAuth = () => {
    if (!state.authRequest) return;
    const deepLink = generatePrivadoLink(state.authRequest);
    window.location.href = deepLink;
  };

  // Render QR code section
  const renderQRSection = () => {
    if (!state.authRequest) return null;

    // RD-1242: a rejected proof replaces the QR and spinner with the reason,
    // while the poll loop above keeps running. The backend's failure is not
    // terminal, and the session ID is visible in the QR code, so a bogus
    // callback from anyone who photographed it must not be able to cancel a
    // login that still completes.
    if (state.failureReason) {
      return (
        <div className="flex flex-col items-center gap-4 py-6" data-testid="auth-error">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-error-light">
            <AlertCircle className="h-8 w-8 text-error-dark" />
          </div>
          <div className="text-center">
            <p className="mb-2 font-medium text-neutral-900">Authentication Failed</p>
            <p className="text-sm text-neutral-500">{authFailureMessage(state.failureReason)}</p>
          </div>
          <Button onClick={startAuth} variant="default" className="w-full mt-2" data-testid="try-again-btn">
            Try Again
          </Button>
        </div>
      );
    }

    const deepLink = generatePrivadoLink(state.authRequest);
    const isMobile = isMobileDevice();

    return (
      <div className="space-y-6" data-testid="qr-section">
        {/* RD-859 brand panel: identifies the credential issuer (Billions)
            and the wallet protocol (Privado ID). Reads correctly whether
            REQUIRE_PROOF_OF_HUMANITY is on (Path B, Billions issuer) or
            off (Path A, plain DID-ownership) — Privado ID is the wallet
            either way.

            RD-1241: Billions is shown only when the deployment reports a
            billions:main state resolver. Without one, a Billions wallet's
            proof is rejected during verification, so advertising it promised a
            sign-in that could not complete. There is no wallet choice to lose
            — the QR and deep link are the same either way and the scanning
            wallet decides the network — so this drops a false promise, not a
            capability. */}
        <PrivadoBrandPanel billionsSupported={billionsSupported} />

        {/* QR Code for desktop */}
        {!isMobile && (
          <div className="flex flex-col items-center gap-4">
            <div className="p-4 bg-white rounded-2xl shadow-lg" role="img" aria-label="QR code for Privado ID authentication" data-testid="qr-code">
              <QRCodeSVG
                value={deepLink}
                size={200}
                level="M"
                includeMargin={false}
                aria-hidden="true"
              />
            </div>
            <p className="text-center text-sm text-neutral-500">
              Scan with your Privado ID wallet
            </p>
          </div>
        )}

        {/* Mobile primary CTA — RD-859: brand the deep-link button as
             "Sign in with Billions/Privado" with both partner logos. */}
        {isMobile && (
          <Button
            onClick={handleMobileAuth}
            className="w-full"
            variant="default"
            size="lg"
            data-testid="privado-signin-btn"
          >
            <span className="inline-flex items-center gap-1 mr-2">
              <BillionsIcon className="h-4 w-auto" />
              <PrivadoIcon className="h-4 w-4" />
            </span>
            Sign in with Billions/Privado
          </Button>
        )}

        {/* Desktop: also show button as fallback */}
        {!isMobile && (
          <div className="border-t border-neutral-200 pt-4">
            <p className="mb-3 text-center text-xs text-neutral-700">
              Or open the wallet on this device
            </p>
            <Button
              onClick={handleMobileAuth}
              className="w-full"
              variant="outline"
              size="sm"
            >
              <ExternalLink className="w-4 h-4 mr-2" />
              Open Wallet App
            </Button>
          </div>
        )}

        {/* Polling indicator */}
        <div className="flex items-center justify-center gap-2 text-sm text-neutral-700" role="status" aria-live="polite">
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
          <span>Waiting for wallet confirmation...</span>
        </div>
      </div>
    );
  };

  return (
    <LoginFrame>
        {/* Auth Card */}
        <Card variant="default" data-testid="auth-card">
          <CardHeader className="text-center">
            <CardTitle data-testid="auth-title">Sign In</CardTitle>
            <CardDescription>
              {activeProvider === 'azuread'
                ? 'Use your Microsoft or corporate account'
                : 'Verify with your Privado ID wallet'}
            </CardDescription>
          </CardHeader>

          {/* Provider tabs — only shown when more than one provider is available */}
          {providers.includes('azuread') && (
            <div className="flex border-b border-neutral-200 mx-6">
              <button
                onClick={() => setActiveProvider('privado')}
                className={`flex-1 py-2 text-sm font-medium transition-colors ${
                  activeProvider === 'privado'
                    ? 'border-b-2 border-primary text-primary'
                    : 'text-neutral-500 hover:text-neutral-700'
                }`}
                data-testid="tab-privado"
              >
                Privado ID
              </button>
              <button
                onClick={() => setActiveProvider('azuread')}
                className={`flex-1 py-2 text-sm font-medium transition-colors ${
                  activeProvider === 'azuread'
                    ? 'border-b-2 border-primary text-primary'
                    : 'text-neutral-500 hover:text-neutral-700'
                }`}
                data-testid="tab-azuread"
              >
                Microsoft
              </button>
            </div>
          )}

          <CardContent>
            {/* Microsoft / Azure AD sign-in panel */}
            {activeProvider === 'azuread' && <MicrosoftLoginPanel>
                <Button
                  onClick={handleAzureLogin}
                  disabled={azureLoading}
                  className="w-full bg-[#0078d4] hover:bg-[#106ebe] text-white"
                  size="lg"
                  data-testid="azure-signin-btn"
                >
                  {azureLoading ? (
                    <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                  ) : (
                    <MicrosoftIcon className="w-5 h-5 mr-2" />
                  )}
                  {azureLoading ? 'Redirecting...' : 'Continue with Microsoft'}
                </Button>
            </MicrosoftLoginPanel>}

            {/* Privado ID flow — hidden when Microsoft tab is active */}
            {activeProvider === 'privado' && (
              <>
            {/* Loading state */}
            {state.step === 'loading' && (
              <div className="flex flex-col items-center gap-4 py-8" role="status" aria-live="polite" data-testid="auth-loading">
                <Loader2 className="h-8 w-8 animate-spin text-primary" aria-hidden="true" />
                <p className="text-neutral-500">Preparing authentication...</p>
              </div>
            )}

            {/* Ready state - show QR */}
            {state.step === 'ready' && renderQRSection()}

            {/* Success state */}
            {state.step === 'success' && (
              <div className="flex flex-col items-center gap-4 py-8" data-testid="auth-success">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-success-light">
                  <CheckCircle2 className="h-8 w-8 text-success-dark" />
                </div>
                <p className="font-medium text-neutral-900">Authentication successful!</p>
                <p className="text-sm text-neutral-500">
                  {isOAuthMode ? 'Redirecting to application...' : 'Redirecting to wallet linking...'}
                </p>
              </div>
            )}

            {/* Humanity verification required */}
            {state.step === 'humanity_required' && (
              <div className="flex flex-col items-center gap-4 py-6">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-warning-light">
                  <AlertCircle className="h-8 w-8 text-warning-dark" />
                </div>
                <div className="text-center">
                  <p className="mb-2 font-medium text-neutral-900">Humanity Verification Required</p>
                  <p className="mb-4 text-sm text-neutral-500">
                    Please complete your ProofOfHumanity verification with Billions to continue.
                  </p>
                </div>
                <Button
                  onClick={() => window.open(state.humanityVerifyUrl!, '_blank')}
                  variant="default"
                  size="lg"
                  className="w-full"
                >
                  <ExternalLink className="w-5 h-5 mr-2" />
                  Verify on Billions
                </Button>
                <Button
                  onClick={startAuth}
                  variant="outline"
                  size="sm"
                  className="w-full mt-2"
                >
                  Try Again
                </Button>
              </div>
            )}

            {/* Polling timeout state */}
            {state.step === 'timed_out' && (
              <div className="flex flex-col items-center gap-4 py-6" data-testid="auth-timeout">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-warning-light">
                  <AlertCircle className="h-8 w-8 text-warning-dark" />
                </div>
                <div className="text-center">
                  <p className="mb-2 font-medium text-neutral-900">Authentication Timed Out</p>
                  <p className="text-sm text-neutral-500">{state.error}</p>
                </div>
                <Button onClick={startAuth} variant="default" className="w-full">
                  Generate New QR Code
                </Button>
                <Button
                  onClick={handleMobileAuth}
                  variant="outline"
                  className="w-full"
                  disabled={!state.authRequest}
                >
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Open Wallet App
                </Button>
              </div>
            )}

            {/* Error state */}
            {state.step === 'error' && (
              <div className="flex flex-col items-center gap-4 py-6" data-testid="auth-error">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-error-light">
                  <AlertCircle className="h-8 w-8 text-error-dark" />
                </div>
                <div className="text-center">
                  <p className="mb-2 font-medium text-neutral-900">Authentication Failed</p>
                  <p className="text-sm text-neutral-500">{state.error}</p>
                </div>
                <Button onClick={startAuth} variant="default" className="w-full mt-2" data-testid="try-again-btn">
                  Try Again
                </Button>
              </div>
            )}
              </>
            )}
          </CardContent>
        </Card>

        {/* Help text — Privado only */}
        {activeProvider === 'privado' && (
          <div className="mt-6 text-center">
            <p className="text-sm text-neutral-700">
              Don't have Privado ID?{' '}
              <a
                href="https://docs.privado.id/docs/wallet/wallet-app/privadoid-app/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline underline-offset-2 hover:text-primary-300"
              >
                Download the wallet
              </a>
            </p>
          </div>
        )}

        {/* Mock login - requires explicit opt-in via VITE_ALLOW_MOCK_LOGIN=true */}
        {allowMockLogin && (
          <DevelopmentIdentityPicker identities={testIdentities.map(identity => ({ id: identity.did, name: identity.name,
            detail: identity.addresses?.[0] ? identity.addresses[0].slice(0, 6) + '...' + identity.addresses[0].slice(-4) : undefined,
            organization: identity.orgs?.[0] }))} disabled={state.step === 'loading'} onSelect={handleMockLoginAs}>
            {/* Fallback mock login button for custom/one-off DIDs */}
            <Button
              onClick={handleMockLogin}
              variant="outline"
              className="w-full border-warning text-warning-dark hover:bg-warning-light"
              disabled={state.step === 'loading'}
              data-testid="mock-login-btn"
            >
              {state.step === 'loading' ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <FlaskConical className="w-4 h-4 mr-2" />
              )}
              Mock Login (Skip Wallet)
            </Button>
          </DevelopmentIdentityPicker>
        )}
    </LoginFrame>
  );
}
