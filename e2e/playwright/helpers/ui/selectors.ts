/**
 * Centralized data-testid selectors for UI tests.
 * Use these selectors consistently across all UI tests.
 */

export const selectors = {
  // Login page
  login: {
    page: '[data-testid="login-page"]',
    header: '[data-testid="login-header"]',
    authCard: '[data-testid="auth-card"]',
    authTitle: '[data-testid="auth-title"]',
    qrSection: '[data-testid="qr-section"]',
    qrCode: '[data-testid="qr-code"]',
    authLoading: '[data-testid="auth-loading"]',
    authSuccess: '[data-testid="auth-success"]',
    authError: '[data-testid="auth-error"]',
    tryAgainBtn: '[data-testid="try-again-btn"]',
    // Dev tools (mock login)
    devTools: '[data-testid="dev-tools"]',
    mockLoginBtn: '[data-testid="mock-login-btn"]',
  },

  // Admin app layout
  admin: {
    app: '[data-testid="admin-app"]',
    header: '[data-testid="admin-header"]',
    logo: '[data-testid="admin-logo"]',
    nav: '[data-testid="admin-nav"]',
  },

  // Navigation tabs. The legacy "Dashboard" tab was renamed to "Diagnostics"
  // and demoted from landing-page status (RBAC is now the default landing tab).
  // `nav.dashboard` is retained as an alias for `nav.diagnostics` so older
  // tests still resolve, but new tests should prefer `nav.diagnostics`.
  nav: {
    diagnostics: '[data-testid="nav-diagnostics"]',
    dashboard: '[data-testid="nav-diagnostics"]',
    logs: '[data-testid="nav-logs"]',
    rbac: '[data-testid="nav-rbac"]',
  },

  // RBAC Manager
  rbac: {
    manager: '[data-testid="rbac-manager"]',
    title: '[data-testid="rbac-title"]',
    tabs: '[data-testid="rbac-tabs"]',
    orgSelector: '[data-testid="org-selector"]',
    // Tab triggers
    tabOrganizations: '[data-testid="tab-organizations"]',
    tabGroups: '[data-testid="tab-groups"]',
    tabUsers: '[data-testid="tab-users"]',
    tabContracts: '[data-testid="tab-contracts"]',
  },

  // Common UI elements
  common: {
    loadingSpinner: '.animate-spin',
    dialog: '[role="dialog"]',
    dialogTitle: '[role="dialog"] h2',
    alertDialog: '[role="alertdialog"]',
  },

  // Batch operations
  batch: {
    // Contract list
    selectAll: '[data-testid="contract-select-all"]',
    toolbar: '[data-testid="selection-toolbar"]',
    moveBtn: '[data-testid="move-to-group-btn"]',
    clearBtn: '[data-testid="clear-selection-btn"]',
    // Group list
    filterAll: '[data-testid="group-filter-all"]',
    filterAuto: '[data-testid="group-filter-auto"]',
    filterManual: '[data-testid="group-filter-manual"]',
    // groupToolbar intentionally same as toolbar — only one is visible at a time
    deleteBtn: '[data-testid="batch-delete-btn"]',
    autoBadge: '[data-testid="auto-badge"]',
    // Move dialog
    moveDialog: '[data-testid="move-dialog"]',
    moveExistingRadio: '[data-testid="move-existing-radio"]',
    moveNewRadio: '[data-testid="move-new-radio"]',
    moveGroupSelect: '[data-testid="move-group-select"]',
    moveNewName: '[data-testid="move-new-name"]',
    moveNewSlug: '[data-testid="move-new-slug"]',
    moveDeleteEmptyCheckbox: '[data-testid="move-delete-empty-checkbox"]',
    moveConfirmBtn: '[data-testid="move-confirm-btn"]',
    moveCancelBtn: '[data-testid="move-cancel-btn"]',
    // Batch delete dialog
    batchDeleteDialog: '[data-testid="batch-delete-dialog"]',
    batchDeleteConfirmBtn: '[data-testid="batch-delete-confirm-btn"]',
    batchDeleteCancelBtn: '[data-testid="batch-delete-cancel-btn"]',
  },
} as const;

/**
 * Helper to get a testid selector string
 */
export function testId(id: string): string {
  return `[data-testid="${id}"]`;
}

/**
 * Helper to build role-based selectors
 */
export const roles = {
  button: (name: string) => ({ role: 'button' as const, name }),
  link: (name: string) => ({ role: 'link' as const, name }),
  tab: (name: string) => ({ role: 'tab' as const, name }),
  heading: (name: string, level?: number) => ({
    role: 'heading' as const,
    name,
    ...(level && { level }),
  }),
  textbox: (name?: string) => ({ role: 'textbox' as const, ...(name && { name }) }),
  row: () => ({ role: 'row' as const }),
  cell: () => ({ role: 'cell' as const }),
  table: () => ({ role: 'table' as const }),
  dialog: (name?: string) => ({ role: 'dialog' as const, ...(name && { name }) }),
} as const;
