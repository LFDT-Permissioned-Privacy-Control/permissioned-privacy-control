// Disclosure TypeScript types mirroring backend models

export type DisclosureRequestStatus = 'pending' | 'approved' | 'rejected' | 'revoked' | 'expired';

export type DisclosureScope = 'activity_logs' | 'transaction_history' | 'full_disclosure';

export type DisclosureReportType = 'activity_summary' | 'sanctions_check' | 'compliance_report';

// DisclosureLevel controls how much address detail is revealed
export type DisclosureLevel = 'full' | 'pseudonymous' | 'redacted';

export interface DisclosureRequest {
  id: string;
  user_id: string;
  // DID of the target user (subject of the request). Surfaced from the
  // backend RequestWithDetails wrapper so the UI can identify the subject
  // by DID instead of the opaque internal user UUID (user_id).
  target_did?: string;
  requester_name: string;
  requester_org?: string;
  requester_did?: string;
  purpose: string;
  scope: DisclosureScope[];
  disclosure_level?: DisclosureLevel;
  status: DisclosureRequestStatus;
  valid_from?: string;
  valid_until?: string;
  request_reference?: string;
  legal_basis?: string;
  created_at: string;
  updated_at: string;
  decided_at?: string;
  decision_reason?: string;
  active_grant_id?: string;
}

export interface DisclosureGrant {
  id: string;
  request_id: string;
  user_id: string;
  token_hash: string;
  scope: DisclosureScope[];
  disclosure_level?: DisclosureLevel;
  valid_from: string;
  valid_until: string;
  revoked_at?: string;
  revoke_reason?: string;
  requester_did?: string;
  reason?: string;
  created_at: string;
  updated_at: string;
}

export interface DisclosureAccessEvent {
  id: string;
  grant_id: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  ip_address?: string;
  user_agent?: string;
  timestamp: string;
}

export interface DisclosureActivityLog {
  id: string;
  user_id: string;
  method: string;
  target_address?: string;
  status: string;
  ip_address?: string;
  timestamp: string;
}

export interface DisclosureActivitySummary {
  total_requests: number;
  methods: Record<string, number>;
  addresses_accessed: string[];
  first_activity?: string;
  last_activity?: string;
}

export interface DisclosureReport {
  type: DisclosureReportType;
  generated_at: string;
  data: unknown;
}

// Input types
export interface CreateDisclosureRequestInput {
  user_external_id: string;
  requester_name: string;
  requester_org?: string;
  requester_did?: string; // DID of auditor who will get access (for block explorer integration)
  purpose: string;
  scope: DisclosureScope[];
  disclosure_level: DisclosureLevel;
  valid_from?: string;
  valid_until?: string;
  request_reference?: string;
  legal_basis?: string;
  // Org context for the request. Required for JWT-based org admins — the
  // backend uses this to enforce requireFullAdminInScope. Omitting it falls
  // back to the system default org, which fails closed for any admin not
  // scoped to that org. Super-admin / dev-mode callers can omit it.
  org_id?: string;
}

export interface ApproveDisclosureResponse {
  grant: DisclosureGrant;
  message: string;
}

export interface RejectDisclosureInput {
  reason?: string;
}

export interface RevokeDisclosureInput {
  reason?: string;
}

// Scope labels for display
export const SCOPE_LABELS: Record<DisclosureScope, string> = {
  activity_logs: 'Activity Logs',
  transaction_history: 'Transaction History',
  full_disclosure: 'Full Disclosure',
};

// Scope descriptions
export const SCOPE_DESCRIPTIONS: Record<DisclosureScope, string> = {
  activity_logs: 'Access to your RPC request logs and method usage',
  transaction_history: 'Access to your transaction history and wallet interactions',
  full_disclosure: 'Complete access to all activity data',
};

// Status labels for display
export const STATUS_LABELS: Record<DisclosureRequestStatus, string> = {
  pending: 'Pending',
  approved: 'Approved',
  rejected: 'Rejected',
  revoked: 'Revoked',
  expired: 'Expired',
};

// Status badge variants
export const STATUS_VARIANTS: Record<DisclosureRequestStatus, 'warning' | 'success' | 'destructive' | 'secondary'> = {
  pending: 'warning',
  approved: 'success',
  rejected: 'destructive',
  revoked: 'destructive',
  expired: 'secondary',
};

// Report type labels
export const REPORT_TYPE_LABELS: Record<DisclosureReportType, string> = {
  activity_summary: 'Activity Summary',
  sanctions_check: 'Sanctions Check',
  compliance_report: 'Compliance Report',
};

// All available scopes
export const ALL_SCOPES: DisclosureScope[] = ['activity_logs', 'transaction_history', 'full_disclosure'];

// All report types
export const ALL_REPORT_TYPES: DisclosureReportType[] = ['activity_summary', 'sanctions_check', 'compliance_report'];

// Disclosure level labels
export const DISCLOSURE_LEVEL_LABELS: Record<DisclosureLevel, string> = {
  full: 'Full (Show Real Addresses)',
  pseudonymous: 'Pseudonymous (Show Aliases)',
  redacted: 'Redacted (Hide Addresses)',
};

// Disclosure level descriptions
export const DISCLOSURE_LEVEL_DESCRIPTIONS: Record<DisclosureLevel, string> = {
  full: 'Auditor sees real ETH addresses - for regulatory subpoenas, law enforcement',
  pseudonymous: 'Auditor sees consistent pseudonyms (Address-A, Address-B) - for compliance audits',
  redacted: 'All addresses replaced with [PRIVATE]; auditor sees timing, direction, gas, and status but cannot correlate counterparties between transactions',
};

// All disclosure levels
export const ALL_DISCLOSURE_LEVELS: DisclosureLevel[] = ['full', 'pseudonymous', 'redacted'];

// Filter for listing disclosures
export interface DisclosureFilter {
  // org_id scopes the list to a single organisation. Admin dashboard
  // callers MUST pass it — the backend gates cross-org reads via
  // requireTargetInScope (Audit C3). For tier-2 admins, the dashboard
  // defaults this to one of their admin orgs at mount; multi-org
  // admins can switch via the DisclosureFilters org-switcher.
  // Optional in the type because user-side disclosure pages don't
  // need it (they're keyed on the caller's own DID).
  org_id?: string;
  status?: DisclosureRequestStatus;
  target_user_id?: string;
  requester_did?: string;
  disclosure_level?: DisclosureLevel;
  date_from?: string;
  date_to?: string;
  limit?: number;
  offset?: number;
}

// Result types for filtered listing
export interface DisclosureListResult {
  requests: DisclosureRequest[];
  total: number;
  limit: number;
  offset: number;
}

export interface GrantListResult {
  grants: DisclosureGrant[];
  total: number;
  limit: number;
  offset: number;
}
