import { Glasses } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuthOptional } from '@/contexts/AuthContext';
import { resolveExplorerUrl } from '@/lib/explorerUrl';
import { useOrgContextOptional } from './RBACManager';

/**
 * RD-928 / RD-994 — primary entry point for the "View as user" flow.
 *
 * Navigates (same tab) to the block-explorer's /view-as handoff, passing the
 * target DID AND the currently-selected org via query params
 * (?did=<did>&org=<org_id>). The explorer FE picks up both on mount, mints an
 * opaque session token via its own BFF (`POST /api/impersonation/start` with
 * { target_did, org_id }), and lands the admin on the explorer home with the
 * banner active. The Open Privacy Suite backend is the authoritative gate; non-tier-2 /
 * org-not-administered / target-not-in-org / unknown target all surface as
 * 403/404 in the explorer UI.
 *
 * RD-994: the org is explicit. For an admin who is tier-2 in multiple orgs,
 * the impersonated session is anchored to the org currently selected in the
 * dashboard's org-context dropdown — not a silent first-match. When no org is
 * selected (e.g. the org-less "all orgs" view), we omit ?org= and the
 * downstream proxy rejects the bare route with a clear 400; the explorer
 * surfaces that as "select an org first".
 *
 * Visibility: parent renders only for tier-2 admins (is_org_admin) — read-only
 * admins (ROA) and super-admin token holders never see this affordance.
 *
 * Configuration: VITE_BLOCK_EXPLORER_URL sets the explorer base URL, resolved
 * from runtime config (see resolveExplorerUrl in @/lib/explorerUrl). When unset
 * in a production build the button is disabled — it deliberately does NOT fall
 * back to localhost (the build-time bake that did so sent devnet admins there).
 */

interface Props {
  /** Target user's DID (external_id on the user row). */
  targetDID: string;
  /** Optional CSS class for the wrapper button. */
  className?: string;
  /** Render variant: 'icon' for tight action cells, 'inline' for detail pages. */
  variant?: 'icon' | 'inline';
}

export function ViewAsInExplorerButton({
  targetDID,
  className,
  variant = 'icon',
}: Props) {
  // Optional auth lookup: in production this is always set (the parent
  // pages live under RequireAdmin which wraps in AuthProvider). In
  // component-unit tests UserDetail/UserList may render without the full
  // app context — fall back to "unknown user" instead of throwing.
  const auth = useAuthOptional();
  const userDID = auth?.userDID ?? null;

  // Optional org-context read: in production the button always renders inside
  // RBACManager (which provides OrgContext), so selectedOrg reflects the
  // dropdown. In isolated unit tests there's no provider — fall back to null
  // (no ?org=) rather than throwing.
  const orgCtx = useOrgContextOptional();
  const selectedOrgId = orgCtx?.selectedOrg?.id ?? null;

  // Self-impersonation is rejected by the Open Privacy Suite backend with 400 anyway;
  // we hide the affordance client-side so the operator never sees a control
  // that can't do anything. Compare lowercase since DID casing isn't
  // semantic. Skip the self-check entirely when AuthProvider isn't in the
  // tree (tests) — the button still renders and the server gate catches
  // any actual self-impersonation attempts.
  if (userDID && userDID.toLowerCase() === targetDID.toLowerCase()) {
    // RD-996: don't collapse the slot on the viewer's own row. Returning null
    // shrank the action cell's flex container, nudging the Ban pill toward the
    // right edge and breaking column alignment against rows that DO render the
    // glasses button. The 'inline' variant lives on a detail page (not a
    // table), so a collapsed slot there is harmless — only the 'icon' variant
    // needs the spacer. Reserve the same footprint the ghost/size-sm button
    // occupies: h-9 (button height) by w-12 (px-4 both sides + the w-4 icon).
    if (variant === 'inline') {
      return null;
    }
    return <span aria-hidden="true" className="inline-block h-9 w-12" />;
  }

  const explorerUrl = resolveExplorerUrl();
  const disabled = explorerUrl === '';

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!explorerUrl) return;
    // RD-994: include the currently-selected org so the impersonated session
    // anchors to the org the admin is looking at. Omitted when no org is
    // selected; the downstream proxy then rejects the bare route (400).
    const orgParam = selectedOrgId
      ? `&org=${encodeURIComponent(selectedOrgId)}`
      : '';
    const url = `${explorerUrl}/view-as?did=${encodeURIComponent(targetDID)}${orgParam}`;
    // Same-tab navigation, not a new tab. Why:
    //
    // AuthProvider stores PP session state in sessionStorage (per-tab by
    // design — see contexts/AuthContext.tsx:98). In Chrome since v88,
    // sessionStorage is genuinely isolated per top-level browsing context —
    // even with the opener reference preserved, a new tab does NOT inherit
    // the opener's sessionStorage when navigating to/from cross-origin URLs.
    // That breaks the OAuth bounce: the new tab arrives at /login with
    // empty sessionStorage → isAuthenticated=false → interactive picker.
    //
    // Same-tab navigation preserves the original tab's sessionStorage across
    // the redirect chain, so PP's silent-SSO useEffect can recognise the
    // existing session and skip the picker.
    //
    // Trade-off: admin leaves the dashboard during the View-as session.
    // Browser back button returns. RD-993's silent-SSO endpoint will let us
    // switch back to new-tab UX without this dance.
    window.location.href = url;
  };

  const disabledTitle = 'Block explorer URL is not configured for this deployment';

  if (variant === 'inline') {
    return (
      <Button
        variant="outline"
        size="sm"
        onClick={handleClick}
        disabled={disabled}
        className={className}
        title={disabled ? disabledTitle : 'Browse the block explorer as this user (same tab)'}
      >
        <Glasses className="w-4 h-4 mr-1.5" />
        View as in Explorer
      </Button>
    );
  }

  // Glasses (not Eye) — distinguishes from the adjacent "view user details"
  // eye icon in the user-list action cell. Eye = "open this user's profile";
  // Glasses = "see the world through this user's lens".
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={handleClick}
      disabled={disabled}
      className={className}
      title={disabled ? disabledTitle : 'View as in Explorer'}
    >
      <Glasses className="w-4 h-4" />
    </Button>
  );
}

export default ViewAsInExplorerButton;
