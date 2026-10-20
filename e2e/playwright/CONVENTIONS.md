# Playwright spec conventions

This file documents the conventions for the UI-only Playwright specs that survive in this repo (`tests/ui/*.spec.ts`). The non-UI specs were migrated to Go in 2026-05 — see `project_playwright_to_go_migration.md` in the project memory.

## Selector convention (RD-965)

Choose selectors in this order. Prefer the earliest option that fits.

1. **`getByRole({ name })`** — when the element has a stable accessible role + name. Works for buttons, links, headings, regions, dialogs. No product-code changes needed.

2. **`getByTestId(...)`** — when the element has no unique accessible name. Add `data-testid="..."` to the product component. Use a stable identifier derived from semantic identity (the ABI param name, the row's primary key) — **never** the ordinal position.

3. **`.nth(N)` / `.first()` / `.last()`** — only when the test deliberately doesn't care which element of N is selected (e.g. "click any two rows for a batch operation"). When you use `.nth()`, add a `// reason:` comment on the line so reviewers don't need to re-derive intent.

### Forbidden patterns

- `.nth(N)` keyed off render order without a `// reason:` comment. Render order changes silently (default sort, column reorder, ABI argument rearrangement) and breaks tests in unrelated PRs.
- `getByText('UI copy')` for non-text content (use `getByRole`/`getByTestId` instead). String literals couple tests to copy/localization.

### Examples

```ts
// ✓ Stable accessible name
await page.getByRole('button', { name: /create grant/i }).click();

// ✓ Stable data-testid keyed on ABI identity (not position)
const fromSelect = selectedEvent.getByTestId('abi-param-from');

// ✓ Any-row semantics with reason
await rows.nth(0).locator('[role="checkbox"]').click(); // reason: pick any 2 rows for the batch test; identity doesn't matter

// ✗ Brittle: depends on render order without intent
const fromSelect = paramSelects.nth(0);
```

## Test scope

Only browser-driven tests belong here. JSON-RPC / admin REST / RBAC enforcement tests live in Go integration tests (`e2e/*.go`) — see `project_playwright_to_go_migration.md`. Don't add a non-UI spec.
