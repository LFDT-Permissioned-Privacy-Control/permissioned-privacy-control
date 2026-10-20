import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ComponentProps } from 'react';
import { toFunctionSelector } from 'viem';
import ContractGrantForm from '../ContractGrantForm';
import { rbacApi } from '@/api/rbac';
import type { ContractGrant, Group, EventSignature } from '@/types/rbac';

const mockGroups: Group[] = [
  {
    id: 'group-1',
    org_id: 'org-1',
    slug: 'auditors',
    name: 'Auditors',
    description: 'Audit group',
    depth: 1,
    path: 'root.auditors',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'group-2',
    org_id: 'org-1',
    slug: 'ops',
    name: 'Ops',
    description: 'Operations group',
    depth: 1,
    path: 'root.ops',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
];

const mockEvents: EventSignature[] = [
  {
    name: 'Transfer',
    signature: 'Transfer(address,address,uint256)',
    topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
    inputs: [
      { name: 'from', type: 'address', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'value', type: 'uint256', indexed: false },
    ],
  },
  {
    name: 'Approval',
    signature: 'Approval(address,address,uint256)',
    topic0: '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
    inputs: [
      { name: 'owner', type: 'address', indexed: true },
      { name: 'spender', type: 'address', indexed: true },
      { name: 'value', type: 'uint256', indexed: false },
    ],
  },
];

function renderForm(props?: Partial<ComponentProps<typeof ContractGrantForm>>) {
  const onClose = vi.fn();
  const onSave = vi.fn();

  render(
    <ContractGrantForm
      orgId="org-1"
      contractAddress="0x1111111111111111111111111111111111111111"
      groups={mockGroups}
      existingGrantGroupIds={[]}
      onClose={onClose}
      onSave={onSave}
      {...props}
    />
  );

  return { onClose, onSave };
}

function mockGrantResponse(grant?: Partial<ContractGrant>) {
  return {
    data: {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: grant?.group_id || 'group-1',
      functions: grant?.functions ?? null,
      event_rules: grant?.event_rules ?? null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: {} },
  } as Awaited<ReturnType<typeof rbacApi.contracts.createGrant>>;
}

/** Stub listEvents so the component's useEffect resolves without hitting the network. */
function stubListEvents(events: EventSignature[] = []) {
  return vi.spyOn(rbacApi.contracts, 'listEvents').mockResolvedValue({
    data: { events },
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: {} },
  } as Awaited<ReturnType<typeof rbacApi.contracts.listEvents>>);
}

describe('ContractGrantForm', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows validation error when submitting without selecting a group', async () => {
    stubListEvents();
    renderForm();

    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  });

  it('disables save button when in specific functions mode with no selectors', async () => {
    const user = userEvent.setup();
    stubListEvents();
    renderForm();

    await user.selectOptions(screen.getByRole('combobox'), 'group-1');
    await user.click(screen.getByRole('radio', { name: /Specific functions only/i }));

    const saveBtn = screen.getByRole('button', { name: 'Next' });
    expect(saveBtn).toBeDisabled();
  });

  it('creates a grant with selected function rules', async () => {
    const user = userEvent.setup();
    stubListEvents();
    const createGrantSpy = vi
      .spyOn(rbacApi.contracts, 'createGrant')
      .mockResolvedValue(mockGrantResponse());
    const { onSave } = renderForm();

    await user.selectOptions(screen.getByRole('combobox'), 'group-1');
    await user.click(screen.getByRole('radio', { name: /Specific functions only/i }));
    await user.click(screen.getByRole('button', { name: /balanceOf/ }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Create Grant' }));

    await waitFor(() => {
      expect(createGrantSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111',
        {
          group_id: 'group-1',
          functions: [{ selector: '0x70a08231' }],
          event_rules: [],
        }
      );
      expect(onSave).toHaveBeenCalledTimes(1);
    });
  });

  it('adds param_rules when self-address constraint is enabled', async () => {
    const user = userEvent.setup();
    stubListEvents();
    const createGrantSpy = vi
      .spyOn(rbacApi.contracts, 'createGrant')
      .mockResolvedValue(mockGrantResponse());
    renderForm();

    await user.selectOptions(screen.getByRole('combobox'), 'group-1');
    await user.click(screen.getByRole('radio', { name: /Specific functions only/i }));
    await user.click(screen.getByRole('button', { name: /balanceOf/ }));
    await user.click(screen.getByLabelText(/account.*must be caller's own address/i));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Create Grant' }));

    await waitFor(() => {
      expect(createGrantSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111',
        {
          group_id: 'group-1',
          functions: [
            {
              selector: '0x70a08231',
              param_rules: [{ index: 0, must_be: 'self' }],
            },
          ],
          event_rules: [],
        }
      );
    });
  });

  it('updates an existing grant in edit mode', async () => {
    const user = userEvent.setup();
    stubListEvents();
    const updateGrantSpy = vi
      .spyOn(rbacApi.contracts, 'updateGrant')
      .mockResolvedValue(mockGrantResponse({ group_id: 'group-2', functions: null }));
    const { onSave } = renderForm({
      grant: {
        id: 'grant-2',
        contract_id: 'contract-1',
        group_id: 'group-2',
        functions: [{ selector: '0x70a08231' }],
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      },
      editMode: 'functions',
    });

    // Group select is hidden in editMode='functions'
    await user.click(screen.getByRole('radio', { name: /All functions/i }));
    await user.click(screen.getByRole('button', { name: 'Save Changes' }));

    await waitFor(() => {
      expect(updateGrantSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111',
        'group-2',
        { functions: null, event_rules: undefined }
      );
      expect(onSave).toHaveBeenCalledTimes(1);
    });
  });

  it('displays backend error message when createGrant returns 400', async () => {
    const user = userEvent.setup();
    stubListEvents();
    vi.spyOn(rbacApi.contracts, 'createGrant').mockRejectedValue({
      response: {
        status: 400,
        data: { error: 'event Transfer: custom param constraints require a contract ABI' },
      },
    });
    renderForm();

    await user.selectOptions(screen.getByRole('combobox'), 'group-1');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Create Grant' }));

    await waitFor(() => {
      const msgs = screen.getAllByText('event Transfer: custom param constraints require a contract ABI');
      expect(msgs.length).toBe(2); // Error shown at top and bottom of form
      expect(msgs[0]).toBeInTheDocument();
    });
  });

  // ===========================================================================
  // Event Rules
  // ===========================================================================

  describe('Event Rules', () => {
    const navigateToEvents = async (user: ReturnType<typeof userEvent.setup>) => {
      await user.selectOptions(screen.getByRole('combobox'), 'group-1');
      await user.click(screen.getByRole('button', { name: 'Next' }));
    };

    it('defaults to "No events visible" mode', async () => {
      const user = userEvent.setup();
      stubListEvents();
      renderForm();

      await navigateToEvents(user);

      const noneRadio = screen.getByRole('radio', { name: /No events visible/i });
      expect(noneRadio).toBeChecked();
    });

    it('shows event picker when switching to "Specific events only"', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      await navigateToEvents(user);

      // Initially no "Visible events" or event picker
      expect(screen.queryByText('Visible events:')).not.toBeInTheDocument();

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      // Should now show the ABI events section
      await waitFor(() => {
        expect(screen.getByText(/Contract events/)).toBeInTheDocument();
      });
    });

    it('fetches events from the API and displays them', async () => {
      const user = userEvent.setup();
      const listEventsSpy = stubListEvents(mockEvents);
      renderForm();

      await navigateToEvents(user);

      // Verify API was called
      expect(listEventsSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111'
      );

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      // Both events should appear in the picker
      await waitFor(() => {
        expect(screen.getByText('Transfer')).toBeInTheDocument();
        expect(screen.getByText('Approval')).toBeInTheDocument();
      });
    });

    it('shows warning when no ABI events are available', async () => {
      const user = userEvent.setup();
      stubListEvents([]); // No events
      renderForm();

      await navigateToEvents(user);

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      await waitFor(() => {
        expect(
          screen.getByText(/No ABI uploaded for this contract.*Upload an ABI to configure event visibility rules/i)
        ).toBeInTheDocument();
      });
    });

    it('adds and removes events from the selected list', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      await navigateToEvents(user);

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      // Wait for events to load, then click Transfer to add it
      await waitFor(() => {
        expect(screen.getByText('Transfer')).toBeInTheDocument();
      });

      // Click the Transfer button in the picker to add it
      await user.click(screen.getByRole('button', { name: /Transfer/ }));

      // Should appear in the "Visible events" list
      expect(screen.getByText('Visible events:')).toBeInTheDocument();

      // The Transfer button in the picker should now be disabled (already added)
      const transferButtons = screen.getAllByRole('button', { name: /Transfer/ });
      const pickerButton = transferButtons.find(b => b.hasAttribute('disabled'));
      expect(pickerButton).toBeTruthy();

      // Remove it by clicking the X button next to the selected event.
      // The remove button is inside the selected event rule's container.
      // Click the last remove-like button (the X on the event rule)
      const eventRuleContainer = screen.getByText('Visible events:').parentElement;
      const removeBtn = eventRuleContainer?.querySelector('button[type="button"]:last-of-type');
      if (removeBtn) {
        await user.click(removeBtn);
      }

      // "Visible events:" label should be gone since no events selected
      expect(screen.queryByText('Visible events:')).not.toBeInTheDocument();
    });

    it('shows param constraint dropdowns for event params', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      await navigateToEvents(user);

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Transfer/ })).toBeInTheDocument();
      });

      // Add Transfer event (has from:address and to:address params)
      await user.click(screen.getByRole('button', { name: /Transfer/ }));

      // Should show param constraint dropdowns for address-type params
      // The EventParamConstraint component renders <select> elements with "Any value" default
      await waitFor(() => {
        expect(screen.getByText('from')).toBeInTheDocument();
        expect(screen.getByText('to')).toBeInTheDocument();
      });
    });

    it('disables save button when in specific events mode with no events', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      await navigateToEvents(user);
      
      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      const saveBtn = screen.getByRole('button', { name: 'Create Grant' });
      expect(saveBtn).toBeDisabled();
    });

    it('submits event_rules as empty array when default "No events visible" is used', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const createGrantSpy = vi
        .spyOn(rbacApi.contracts, 'createGrant')
        .mockResolvedValue(mockGrantResponse());
      renderForm();

      await navigateToEvents(user);

      // Default is "No events visible"
      await user.click(screen.getByRole('button', { name: 'Create Grant' }));

      await waitFor(() => {
        expect(createGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          expect.objectContaining({
            event_rules: [],
          })
        );
      });
    });

    it('submits event_rules with selected events', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const createGrantSpy = vi
        .spyOn(rbacApi.contracts, 'createGrant')
        .mockResolvedValue(mockGrantResponse());
      renderForm();

      await navigateToEvents(user);

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      // Wait for events, then add Transfer
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Transfer/ })).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /Transfer/ }));
      await user.click(screen.getByRole('button', { name: 'Create Grant' }));

      await waitFor(() => {
        expect(createGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          expect.objectContaining({
            event_rules: [
              { topic0: mockEvents[0].topic0, name: 'Transfer', param_rules: null },
            ],
          })
        );
      });
    });

    it('submits event_rules with param_rules when self constraint is selected', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const createGrantSpy = vi
        .spyOn(rbacApi.contracts, 'createGrant')
        .mockResolvedValue(mockGrantResponse());
      renderForm();

      await navigateToEvents(user);

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Transfer/ })).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /Transfer/ }));

      // Select "Caller's address (self)" from the param constraint dropdown for the first address param
      // The EventParamConstraint renders a <select> per param
      await waitFor(() => {
        expect(screen.getByText('from')).toBeInTheDocument();
      });
      // Find all select elements within the event param area and pick the first one (from param)
      const selects = screen.getAllByRole('combobox');
      // The first combobox is the group selector, param selects come after
      const fromParamSelect = selects.find(s => {
        const options = Array.from(s.querySelectorAll('option'));
        return options.some(o => o.textContent?.includes("Caller's address"));
      });
      if (fromParamSelect) {
        await user.selectOptions(fromParamSelect, 'self');
      }
      await user.click(screen.getByRole('button', { name: 'Create Grant' }));

      await waitFor(() => {
        expect(createGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          expect.objectContaining({
            event_rules: [
              {
                topic0: mockEvents[0].topic0,
                name: 'Transfer',
                param_rules: [{ index: 0, must_be: 'self' }],
              },
            ],
          })
        );
      });
    });

    it('pre-populates event rules in edit mode', async () => {
      stubListEvents(mockEvents);
      renderForm({
        grant: {
          id: 'grant-edit',
          contract_id: 'contract-1',
          group_id: 'group-1',
          functions: null,
          event_rules: [
            { topic0: mockEvents[0].topic0, name: 'Transfer' },
          ],
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
        editMode: 'events',
      });

      // Should be in "Specific events only" mode
      expect(screen.getByRole('radio', { name: /Specific events only/i })).toBeChecked();

      // Transfer should appear in the visible events list
      expect(screen.getByText('Visible events:')).toBeInTheDocument();
      expect(screen.getByText('Transfer')).toBeInTheDocument();
    });

    it('"No events visible" is the default mode', async () => {
      const user = userEvent.setup();
      stubListEvents();
      renderForm();

      await navigateToEvents(user);

      const noneRadio = screen.getByRole('radio', { name: /No events visible/i });
      expect(noneRadio).toBeInTheDocument();
      expect(noneRadio).toBeChecked();
    });

    it('selecting "No events visible" hides the event picker', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      await navigateToEvents(user);

      // Switch to specific first to see the picker
      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));
      await waitFor(() => {
        expect(screen.getByText(/Contract events/)).toBeInTheDocument();
      });

      // Switch to "No events visible" — picker should disappear
      await user.click(screen.getByRole('radio', { name: /No events visible/i }));
      expect(screen.queryByText(/Contract events/)).not.toBeInTheDocument();
      expect(screen.queryByText('Visible events:')).not.toBeInTheDocument();
    });

    it('submits event_rules as empty array when "No events visible" is selected', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const createGrantSpy = vi
        .spyOn(rbacApi.contracts, 'createGrant')
        .mockResolvedValue(mockGrantResponse());
      renderForm();

      await navigateToEvents(user);

      await user.click(screen.getByRole('radio', { name: /No events visible/i }));
      await user.click(screen.getByRole('button', { name: 'Create Grant' }));

      await waitFor(() => {
        expect(createGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          expect.objectContaining({
            event_rules: [],
          })
        );
      });
    });

    it('pre-selects "No events visible" in edit mode when event_rules is empty array', async () => {
      stubListEvents(mockEvents);
      renderForm({
        grant: {
          id: 'grant-none',
          contract_id: 'contract-1',
          group_id: 'group-1',
          functions: null,
          event_rules: [],
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
        editMode: 'events',
      });

      expect(screen.getByRole('radio', { name: /No events visible/i })).toBeChecked();
      expect(screen.getByRole('radio', { name: /Specific events only/i })).not.toBeChecked();

      // The event picker should not be visible
      expect(screen.queryByText(/Contract events/)).not.toBeInTheDocument();
      expect(screen.queryByText('Visible events:')).not.toBeInTheDocument();
    });

    it('updates event_rules in edit mode', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const updateGrantSpy = vi
        .spyOn(rbacApi.contracts, 'updateGrant')
        .mockResolvedValue(mockGrantResponse({ group_id: 'group-1' }));
      renderForm({
        grant: {
          id: 'grant-edit',
          contract_id: 'contract-1',
          group_id: 'group-1',
          functions: null,
          event_rules: [
            { topic0: mockEvents[0].topic0, name: 'Transfer' },
          ],
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
        editMode: 'events',
      });

      // Switch to "No events visible"
      await user.click(screen.getByRole('radio', { name: /No events visible/i }));
      await user.click(screen.getByRole('button', { name: 'Save Changes' }));

      await waitFor(() => {
        expect(updateGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          'group-1',
          { functions: null, event_rules: [] }
        );
      });
    });
  });
});

// ---------------------------------------------------------------------------
// RD-1201: functions tri-state through the form — all (null), none ([]),
// specific ([rules]) must each round-trip create/edit without collapsing.
// ---------------------------------------------------------------------------

describe('ContractGrantForm — functions tri-state (RD-1201)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const editableGrant = (functions: ContractGrant['functions']): ContractGrant => ({
    id: 'grant-3',
    contract_id: 'contract-1',
    group_id: 'group-1',
    functions,
    event_rules: null,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  });

  it('pre-selects "All functions" when editing a grant with functions: null', async () => {
    stubListEvents();
    renderForm({ grant: editableGrant(null), editMode: 'functions' });

    expect(screen.getByRole('radio', { name: /All functions/i })).toBeChecked();
    expect(screen.getByRole('radio', { name: /No functions/i })).not.toBeChecked();
  });

  it('pre-selects "No functions" when editing a grant with functions: [] — not "All"', async () => {
    stubListEvents();
    renderForm({ grant: editableGrant([]), editMode: 'functions' });

    expect(screen.getByRole('radio', { name: /No functions/i })).toBeChecked();
    expect(screen.getByRole('radio', { name: /All functions/i })).not.toBeChecked();
  });

  it('pre-selects "Specific functions only" for a non-empty rule list', async () => {
    stubListEvents();
    renderForm({
      grant: editableGrant([{ selector: '0x70a08231' }]),
      editMode: 'functions',
    });

    expect(screen.getByRole('radio', { name: /Specific functions only/i })).toBeChecked();
  });

  it('creates a grant with functions: [] when "No functions" is selected', async () => {
    const user = userEvent.setup();
    stubListEvents();
    const createGrantSpy = vi
      .spyOn(rbacApi.contracts, 'createGrant')
      .mockResolvedValue(mockGrantResponse({ functions: [] }));
    const { onSave } = renderForm();

    await user.selectOptions(screen.getByRole('combobox'), 'group-1');
    await user.click(screen.getByRole('radio', { name: /No functions/i }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Create Grant' }));

    await waitFor(() => {
      expect(createGrantSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111',
        expect.objectContaining({ group_id: 'group-1', functions: [] })
      );
      expect(onSave).toHaveBeenCalledTimes(1);
    });
    const sent = createGrantSpy.mock.calls[0][2] as { functions: unknown };
    expect(sent.functions).toEqual([]);
    expect(sent.functions).not.toBeNull();
  });

  it('submits functions: [] when "No functions" is selected', async () => {
    const user = userEvent.setup();
    stubListEvents();
    const updateGrantSpy = vi
      .spyOn(rbacApi.contracts, 'updateGrant')
      .mockResolvedValue(mockGrantResponse({ group_id: 'group-1', functions: [] }));
    const { onSave } = renderForm({ grant: editableGrant(null), editMode: 'functions' });

    await user.click(screen.getByRole('radio', { name: /No functions/i }));
    await user.click(screen.getByRole('button', { name: 'Save Changes' }));

    await waitFor(() => {
      expect(updateGrantSpy.mock.calls).toHaveLength(1);
    });
    // event_rules passes through unchanged in editMode 'functions' — this
    // fixture's grant has event_rules: null, so null is re-sent verbatim.
    expect(updateGrantSpy.mock.calls[0]).toEqual([
      'org-1',
      '0x1111111111111111111111111111111111111111',
      'group-1',
      { functions: [], event_rules: null },
    ]);
    expect(onSave).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// RD-1205: tuple / nested-tuple / tuple-array selectors through the form.
// The expected selectors are derived from the canonical STRING signatures —
// an independent path from the component, which starts from the ABI OBJECT.
// A hand-built signature would hash the literal word "tuple" and never match
// real calldata.
// ---------------------------------------------------------------------------

describe('ContractGrantForm — tuple selectors (RD-1205)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const tupleAbi = JSON.stringify([
    {
      type: 'function',
      name: 'setWorkflowDetails',
      stateMutability: 'nonpayable',
      inputs: [
        { name: 'id', type: 'uint256' },
        {
          name: 'details',
          type: 'tuple',
          components: [
            { name: 'label', type: 'string' },
            { name: 'uri', type: 'string' },
          ],
        },
      ],
      outputs: [],
    },
    {
      type: 'function',
      name: 'setNested',
      stateMutability: 'nonpayable',
      inputs: [
        {
          name: 'outer',
          type: 'tuple',
          components: [
            { name: 'inner', type: 'tuple', components: [{ name: 'x', type: 'uint256' }] },
            { name: 'flag', type: 'bool' },
          ],
        },
      ],
      outputs: [],
    },
    {
      type: 'function',
      name: 'batchSet',
      stateMutability: 'nonpayable',
      inputs: [
        {
          name: 'items',
          type: 'tuple[]',
          components: [
            { name: 'key', type: 'bytes32' },
            { name: 'value', type: 'uint256' },
          ],
        },
      ],
      outputs: [],
    },
  ]);

  const expectations: Array<{ fn: string; canonical: string }> = [
    { fn: 'setWorkflowDetails', canonical: 'setWorkflowDetails(uint256,(string,string))' },
    { fn: 'setNested', canonical: 'setNested(((uint256),bool))' },
    { fn: 'batchSet', canonical: 'batchSet((bytes32,uint256)[])' },
  ];

  it.each(expectations)(
    'adds $fn from the ABI picker with the canonical tuple selector',
    async ({ fn, canonical }) => {
      const user = userEvent.setup();
      stubListEvents();
      const createGrantSpy = vi
        .spyOn(rbacApi.contracts, 'createGrant')
        .mockResolvedValue(mockGrantResponse());
      const { onSave } = renderForm({ contractAbi: tupleAbi });

      // Pick a group, switch to specific-functions mode, add from the picker,
      // then step through the two-step create flow (Next → Create Grant).
      await user.selectOptions(screen.getByRole('combobox'), 'group-1');
      await user.click(screen.getByRole('radio', { name: /Specific functions only/i }));
      await user.click(await screen.findByRole('button', { name: new RegExp(fn) }));
      await user.click(screen.getByRole('button', { name: 'Next' }));
      await user.click(screen.getByRole('button', { name: 'Create Grant' }));

      const expectedSelector = toFunctionSelector(canonical);
      await waitFor(() => {
        expect(createGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          expect.objectContaining({
            functions: [expect.objectContaining({ selector: expectedSelector })],
          })
        );
        expect(onSave).toHaveBeenCalledTimes(1);
      });
    }
  );
});
