import { useState, useMemo, useEffect, useRef } from 'react';
import { toFunctionSelector, toFunctionSignature } from 'viem';
import { rbacApi } from '@/api/rbac';
import type { Group, ContractGrant, CreateContractGrantInput, FunctionRule, EventRule, ParamRule, EventSignature } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { AlertCircle, Save, X, Loader2, Users, Plus, FileJson, Radio } from 'lucide-react';

interface ContractGrantFormProps {
  orgId: string;
  contractAddress: string;
  contractAbi?: string; // Contract ABI JSON string
  grant?: ContractGrant | null; // If provided, we're editing
  groups: Group[];
  existingGrantGroupIds: string[]; // Groups that already have grants (for filtering)
  onClose: () => void;
  onSave: () => void;
  editMode?: 'add' | 'functions' | 'events';
}

// Parsed ABI function entry
interface AbiFunctionInput {
  index: number;
  name: string;
  type: string;
}

interface AbiFunction {
  selector: string;
  name: string;
  signature: string;
  stateMutability?: string;
  inputs: AbiFunctionInput[];
}

// Common function selectors with human-readable names
const COMMON_SELECTORS: Record<string, string> = {
  '0x70a08231': 'balanceOf(address)',
  '0x18160ddd': 'totalSupply()',
  '0xa9059cbb': 'transfer(address,uint256)',
  '0x23b872dd': 'transferFrom(address,address,uint256)',
  '0x095ea7b3': 'approve(address,uint256)',
  '0xdd62ed3e': 'allowance(address,address)',
  '0x06fdde03': 'name()',
  '0x95d89b41': 'symbol()',
  '0x313ce567': 'decimals()',
};

// Known parameter info for common selectors (used when ABI is not available)
const COMMON_SELECTOR_PARAMS: Record<string, AbiFunctionInput[]> = {
  '0x70a08231': [{ index: 0, name: 'account', type: 'address' }],
  '0xa9059cbb': [{ index: 0, name: 'to', type: 'address' }],
  '0x23b872dd': [
    { index: 0, name: 'from', type: 'address' },
    { index: 1, name: 'to', type: 'address' },
  ],
  '0x095ea7b3': [{ index: 0, name: 'spender', type: 'address' }],
  '0xdd62ed3e': [
    { index: 0, name: 'owner', type: 'address' },
    { index: 1, name: 'spender', type: 'address' },
  ],
};

// Validate function selector format (0x + 8 hex chars)
const isValidSelector = (selector: string): boolean => {
  return /^0x[a-fA-F0-9]{8}$/.test(selector);
};

// Validate hex value for custom param constraints — accepts any 0x-prefixed hex
const isValidHexValue = (value: string): boolean => {
  return /^0x[a-fA-F0-9]+$/.test(value);
};

// Pad a hex value to the correct byte length for the ABI type.
// address → 20 bytes, uint*/int* → 32 bytes, bytes32 → 32 bytes, etc.
// Left-pads with zeros for numeric types, right-pads for bytesN.
function padHexForType(hex: string, paramType: string): string {
  const raw = hex.slice(2); // strip 0x
  const targetBytes = paramType === 'address' ? 20
    : paramType.startsWith('bytes') ? parseInt(paramType.replace('bytes', '')) || 32
    : 32; // uint*, int*, bool, fallback
  const targetChars = targetBytes * 2;
  if (raw.length >= targetChars) return '0x' + raw.slice(0, targetChars);
  // Left-pad for numbers/addresses, right-pad for bytesN
  if (paramType.startsWith('bytes') && paramType !== 'bytes') {
    return '0x' + raw.padEnd(targetChars, '0');
  }
  return '0x' + raw.padStart(targetChars, '0');
}

// Get constraint dropdown options based on ABI type
function getConstraintOptions(paramType: string): { value: string; label: string }[] {
  const options = [{ value: 'any', label: 'Any value' }];

  if (paramType === 'address') {
    options.push({ value: 'self', label: "Caller's address (self)" });
    options.push({ value: 'custom', label: 'Custom address' });
  } else if (paramType === 'bool') {
    options.push({ value: 'true', label: 'True' });
    options.push({ value: 'false', label: 'False' });
  } else if (paramType.startsWith('uint') || paramType.startsWith('int')) {
    options.push({ value: 'custom', label: 'Custom value' });
  } else if (paramType.startsWith('bytes')) {
    options.push({ value: 'custom', label: 'Custom value' });
  } else {
    options.push({ value: 'custom', label: 'Custom hex value' });
  }

  return options;
}

// Get placeholder text for custom value input based on ABI type
function getCustomPlaceholder(paramType: string): string {
  if (paramType === 'address') return '0x address (e.g. 0xd8dA6BF...)';
  if (paramType.startsWith('uint')) return '0x hex number (e.g. 0x2a for 42)';
  if (paramType === 'bytes32') return '0x hex (auto-padded to 32 bytes)';
  if (paramType.startsWith('bytes')) return '0x hex bytes';
  return '0x hex value';
}

// Inline component for a single event parameter constraint
function EventParamConstraint({
  param,
  constraintMode,
  customValue,
  onChange,
}: {
  param: { index: number; name: string; type: string; indexed: boolean };
  constraintMode: string; // 'any' | 'self' | 'custom' | 'true' | 'false'
  customValue: string;
  onChange: (mustBe: string) => void; // '' to remove, 'self' or '0x...' to set
}) {
  const [localMode, setLocalMode] = useState(constraintMode);
  const [localCustom, setLocalCustom] = useState(customValue);
  const [customError, setCustomError] = useState('');
  const options = getConstraintOptions(param.type);

  // Sync from parent prop only when the parent's saved value actually changes
  useEffect(() => {
    setLocalMode(constraintMode);
  }, [constraintMode]);

  const handleModeChange = (mode: string) => {
    setCustomError('');
    setLocalMode(mode);
    switch (mode) {
      case 'any':
        onChange('');
        break;
      case 'self':
        onChange('self');
        break;
      case 'true':
        onChange('0x01');
        break;
      case 'false':
        onChange('0x00');
        break;
      case 'custom':
        // Don't call onChange yet — wait for user to enter a value and click Set
        setLocalCustom('');
        break;
    }
  };

  const handleCustomApply = () => {
    const val = localCustom.trim().toLowerCase();
    if (!val) {
      setCustomError('Value is required');
      return;
    }
    if (!isValidHexValue(val)) {
      setCustomError('Must be a 0x-prefixed hex value (e.g. 0x1, 0xabcd)');
      return;
    }
    setCustomError('');
    onChange(padHexForType(val, param.type));
  };

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-1.5">
        <code className="font-mono text-xs text-neutral-700">
          {param.name || `param[${param.index}]`}
        </code>
        {param.indexed && (
          <span className="px-1 py-0.5 rounded text-[10px] bg-neutral-200 text-neutral-500">idx</span>
        )}
        <span className="text-[10px] text-neutral-400">{param.type}</span>
        <select
          value={localMode}
          onChange={e => handleModeChange(e.target.value)}
          // Stable identifier for e2e tests (RD-965). Prefer the ABI
          // param name; fall back to the positional index for unnamed
          // params. Lets tests select by semantic identity instead of
          // render order.
          data-testid={`abi-param-${param.name || `idx-${param.index}`}`}
          className="ml-auto px-1.5 py-1 text-xs border border-neutral-200 rounded focus:outline-none focus:ring-1 focus:ring-primary max-w-[160px]"
        >
          {options.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>
      {localMode === 'custom' && (
        <div className="pl-2 space-y-1">
          <div className="flex items-center gap-1.5">
            <input
              type="text"
              value={localCustom}
              onChange={e => { setLocalCustom(e.target.value); setCustomError(''); }}
              placeholder={getCustomPlaceholder(param.type)}
              className="flex-1 min-w-0 px-2 py-1 text-xs font-mono border border-neutral-200 rounded focus:outline-none focus:ring-1 focus:ring-primary"
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); handleCustomApply(); } }}
            />
            <button
              type="button"
              onClick={handleCustomApply}
              className="px-2 py-1 text-xs rounded bg-primary text-white hover:bg-primary-700 transition-colors"
            >
              Set
            </button>
          </div>
          {customError && (
            <p className="text-[10px] text-red-600">{customError}</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function ContractGrantForm({
  orgId,
  contractAddress,
  contractAbi,
  grant,
  groups,
  existingGrantGroupIds,
  onClose,
  onSave,
  editMode = 'add',
}: ContractGrantFormProps) {
  const [selectedGroupId, setSelectedGroupId] = useState<string>(grant?.group_id || '');
  const [functionMode, setFunctionMode] = useState<'all' | 'specific' | 'none'>(() => {
    // null/undefined = all functions; [] = no functions (events only); [..] = specific.
    if (!grant || grant.functions == null) return 'all';
    return grant.functions.length === 0 ? 'none' : 'specific';
  });
  const [functions, setFunctions] = useState<FunctionRule[]>(grant?.functions || []);
  const [newSelector, setNewSelector] = useState('');
  const [eventMode, setEventMode] = useState<'all' | 'specific' | 'none'>(() => {
    if (grant?.event_rules === '*') return 'all';
    if (grant?.event_rules === undefined || grant?.event_rules === null) return 'none';
    if (grant.event_rules.length === 0) return 'none';
    return 'specific';
  });
  const [eventRules, setEventRules] = useState<EventRule[]>(
    grant?.event_rules && grant.event_rules !== '*' ? grant.event_rules : []
  );
  const [availableEvents, setAvailableEvents] = useState<EventSignature[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState(1);
  const formRef = useRef<HTMLFormElement>(null);

  const isEditing = !!grant;

  // Determine what to show based on mode and step
  const showGroupSelect = editMode === 'add' && step === 1;
  const showFunctions = editMode === 'functions' || (editMode === 'add' && step === 1);
  const showEvents = editMode === 'events' || (editMode === 'add' && step === 2);

  // Fetch available events from the backend (ABI-parsed)
  useEffect(() => {
    const fetchEvents = async () => {
      setEventsLoading(true);
      try {
        const res = await rbacApi.contracts.listEvents(orgId, contractAddress);
        setAvailableEvents(res.data?.events || []);
      } catch {
        // If events can't be loaded, we just won't show the picker
        setAvailableEvents([]);
      } finally {
        setEventsLoading(false);
      }
    };
    fetchEvents();
  }, [orgId, contractAddress]);

  // Parse ABI to extract function selectors
  const abiFunctions = useMemo<AbiFunction[]>(() => {
    if (!contractAbi) return [];
    try {
      const parsed = JSON.parse(contractAbi);
      if (!Array.isArray(parsed)) return [];

      const results: AbiFunction[] = [];
      for (const item of parsed) {
        if (item.type !== 'function') continue;
        const abiInputs = item.inputs || [];
        try {
          // Derive selector + canonical signature from the ABI item via viem,
          // which expands struct/tuple params to their component types
          // (e.g. `(string,string)`). Building the signature by hand from
          // input.type is wrong for tuples: a struct param's type is the
          // literal "tuple", so `setWorkflowDetails(uint256,tuple)` hashes to a
          // selector that never matches real calldata.
          const selector = toFunctionSelector(item);
          results.push({
            selector,
            name: item.name,
            signature: toFunctionSignature(item),
            stateMutability: item.stateMutability,
            inputs: abiInputs.map((input: { name: string; type: string }, idx: number) => ({
              index: idx,
              name: input.name,
              type: input.type,
            })),
          });
        } catch {
          // Skip invalid signatures
        }
      }
      return results;
    } catch {
      return [];
    }
  }, [contractAbi]);

  // Available groups (exclude ones that already have grants, except current grant's group)
  const availableGroups = groups.filter(
    g => !existingGrantGroupIds.includes(g.id) || g.id === grant?.group_id
  );

  // Get the selected group's details to show its claims
  const selectedGroup = groups.find(g => g.id === selectedGroupId);

  // Helper to check if a selector is already in the functions list
  const hasFunctionSelector = (selector: string): boolean => {
    return functions.some(f => f.selector.toLowerCase() === selector.toLowerCase());
  };

  const handleAddSelector = () => {
    const selector = newSelector.trim().toLowerCase();
    if (!selector) return;

    if (!isValidSelector(selector)) {
      setError('Invalid selector format. Must be 0x followed by 8 hex characters (e.g., 0x70a08231)');
      return;
    }

    if (hasFunctionSelector(selector)) {
      setError('This selector is already added');
      return;
    }

    setFunctions([...functions, { selector }]);
    setNewSelector('');
    setError(null);
  };

  const handleRemoveSelector = (selector: string) => {
    setFunctions(functions.filter(f => f.selector.toLowerCase() !== selector.toLowerCase()));
  };

  const handleAddCommonSelector = (selector: string) => {
    if (!hasFunctionSelector(selector)) {
      setFunctions([...functions, { selector }]);
    }
  };

  // Toggle a param_rule on a function rule
  const handleToggleParamRule = (selector: string, paramIndex: number, checked: boolean) => {
    setFunctions(prev =>
      prev.map(rule => {
        if (rule.selector.toLowerCase() !== selector.toLowerCase()) return rule;
        const existing = rule.param_rules || [];
        if (checked) {
          // Add the param rule if not already present
          if (existing.some(pr => pr.index === paramIndex)) return rule;
          const newRule: ParamRule = { index: paramIndex, must_be: 'self' };
          return { ...rule, param_rules: [...existing, newRule] };
        } else {
          // Remove the param rule
          const filtered = existing.filter(pr => pr.index !== paramIndex);
          return { ...rule, param_rules: filtered.length > 0 ? filtered : null };
        }
      })
    );
  };

  // Check if an event topic0 is already in the event rules list
  const hasEventTopic = (topic0: string): boolean => {
    return eventRules.some(r => r.topic0.toLowerCase() === topic0.toLowerCase());
  };

  const handleAddEvent = (event: EventSignature) => {
    if (!hasEventTopic(event.topic0)) {
      setEventRules([...eventRules, {
        topic0: event.topic0,
        name: event.name,
        param_rules: event.default_param_rules || null,
      }]);
    }
  };

  const handleRemoveEvent = (topic0: string) => {
    setEventRules(eventRules.filter(r => r.topic0.toLowerCase() !== topic0.toLowerCase()));
  };

  // Set or remove a param_rule on an event rule.
  // mustBe = '' means remove the constraint ("Any value").
  // mustBe = 'self' or '0x...' sets the constraint.
  const handleSetEventParamRule = (topic0: string, paramIndex: number, mustBe: string) => {
    setEventRules(prev =>
      prev.map(rule => {
        if (rule.topic0.toLowerCase() !== topic0.toLowerCase()) return rule;
        const existing = rule.param_rules || [];
        if (!mustBe) {
          // Remove constraint for this param
          const filtered = existing.filter(pr => pr.index !== paramIndex);
          return { ...rule, param_rules: filtered.length > 0 ? filtered : null };
        }
        // Add or update constraint
        const updated = existing.filter(pr => pr.index !== paramIndex);
        updated.push({ index: paramIndex, must_be: mustBe });
        return { ...rule, param_rules: updated };
      })
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!selectedGroupId) {
      setError('Please select a group');
      return;
    }

    if (showFunctions && functionMode === 'specific' && functions.length === 0) {
      setError('Please add at least one function selector, or select "All functions"');
      return;
    }

    if (showEvents && eventMode === 'specific' && eventRules.length === 0) {
      setError('Please add at least one event, or select "No events visible"');
      return;
    }

    // Wizard Next Step
    if (editMode === 'add' && step === 1) {
      setStep(2);
      return;
    }

    setSaving(true);

    try {
      const resolvedEventRules = eventMode === 'all' ? '*' : eventMode === 'none' ? [] : eventRules;
      // all → null (any function); none → [] (deny all, events-only); specific → the list.
      const inputFunctions = functionMode === 'all' ? null : functionMode === 'none' ? [] : functions;

      if (isEditing) {
        // Update existing grant - preserve the section not being edited
        const updateData: Partial<CreateContractGrantInput> = {};
        
        if (editMode === 'functions') {
          updateData.functions = inputFunctions;
          updateData.event_rules = grant.event_rules; // Preserve existing
        } else if (editMode === 'events') {
          updateData.event_rules = resolvedEventRules;
          updateData.functions = grant.functions; // Preserve existing
        } else {
          // Should not happen with current logic since 'add' mode means isEditing = false,
          // but just in case we allow editing both at once in the future
          updateData.functions = inputFunctions;
          updateData.event_rules = resolvedEventRules;
        }

        await rbacApi.contracts.updateGrant(orgId, contractAddress, grant.group_id, updateData);
      } else {
        // Create new grant
        const input: CreateContractGrantInput = {
          group_id: selectedGroupId,
          functions: inputFunctions,
          event_rules: resolvedEventRules,
        };
        await rbacApi.contracts.createGrant(orgId, contractAddress, input);
      }
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save grant:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save grant. Please try again.');
      }
      if (typeof formRef.current?.scrollTo === 'function') {
        formRef.current.scrollTo({ top: 0, behavior: 'smooth' });
      }
    } finally {
      setSaving(false);
    }
  };

  // Get selector label (from ABI if available, then common selectors, then just the selector)
  const getSelectorLabel = (selector: string) => {
    // First check ABI functions
    const abiFunc = abiFunctions.find(f => f.selector.toLowerCase() === selector.toLowerCase());
    if (abiFunc) return abiFunc.signature;
    // Then check common selectors
    return COMMON_SELECTORS[selector] || selector;
  };

  return (
    <form ref={formRef} onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      {/* Group selection */}
      {showGroupSelect && (
        <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">
          Select Group
        </label>
        <p className="text-xs text-neutral-400 mb-2">
          Choose which group can access this contract. The group's claims (set in the Groups tab) determine their permissions.
        </p>
        <select
          value={selectedGroupId}
          onChange={e => setSelectedGroupId(e.target.value)}
          disabled={isEditing} // Can't change group when editing
          className="w-full px-3 py-2 border border-neutral-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent disabled:bg-neutral-100 disabled:text-neutral-500"
        >
          <option value="">Select a group...</option>
          {availableGroups.map(group => (
            <option key={group.id} value={group.id}>
              {group.name} ({group.path})
            </option>
          ))}
        </select>
        {!isEditing && availableGroups.length === 0 && (
          <p className="text-xs text-red-600">
            All groups in this organization already have access to this contract.
          </p>
        )}
      </div>
      )}

      {/* Show selected group's info */}
      {showGroupSelect && selectedGroup && (
        <div className="p-4 rounded-lg bg-primary-50 border border-primary-50">
          <div className="flex items-center gap-3 mb-2">
            <Users className="w-5 h-5 text-primary" />
            <p className="font-medium text-neutral-900">{selectedGroup.name}</p>
          </div>
          <p className="text-xs text-neutral-500">
            This group's members will have access to this contract based on the group's claim settings.
          </p>
        </div>
      )}

      {/* Function Access */}
      {showFunctions && (
        <div className="space-y-3">
        <label className="block text-sm font-medium text-neutral-700">
          Function Access
        </label>
        <p className="text-xs text-neutral-400">
          Allow all functions, restrict to specific selectors, or allow none (an
          events-only / monitoring grant).
        </p>

        {/* Radio options */}
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 border border-neutral-200 rounded-lg cursor-pointer hover:bg-neutral-100 transition-colors">
            <input
              type="radio"
              name="functionMode"
              value="all"
              checked={functionMode === 'all'}
              onChange={() => setFunctionMode('all')}
              className="w-4 h-4 text-primary focus:ring-primary"
            />
            <div>
              <p className="text-sm font-medium text-neutral-900">All functions</p>
              <p className="text-xs text-neutral-500">Group can call any function on this contract</p>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 border border-neutral-200 rounded-lg cursor-pointer hover:bg-neutral-100 transition-colors">
            <input
              type="radio"
              name="functionMode"
              value="specific"
              checked={functionMode === 'specific'}
              onChange={() => setFunctionMode('specific')}
              className="w-4 h-4 text-primary focus:ring-primary"
            />
            <div>
              <p className="text-sm font-medium text-neutral-900">Specific functions only</p>
              <p className="text-xs text-neutral-500">Restrict to selected function selectors</p>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 border border-neutral-200 rounded-lg cursor-pointer hover:bg-neutral-100 transition-colors">
            <input
              type="radio"
              name="functionMode"
              value="none"
              checked={functionMode === 'none'}
              onChange={() => setFunctionMode('none')}
              className="w-4 h-4 text-primary focus:ring-primary"
            />
            <div>
              <p className="text-sm font-medium text-neutral-900">No functions</p>
              <p className="text-xs text-neutral-500">
                Group cannot call any function — events only (combine with event visibility below)
              </p>
            </div>
          </label>
        </div>

        {/* Function selector input (shown when specific mode) */}
        {functionMode === 'specific' && (
          <div className="space-y-3 pt-2">
            {/* Warning when no ABI is available */}
            {!contractAbi && (
              <div className="p-4 rounded-lg bg-warning-light border border-amber-200 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-amber-800 flex-shrink-0 mt-0.5" />
                <span className="text-amber-800 text-sm">
                  No ABI uploaded for this contract. Function names shown are based on common ERC20 selectors and may not match this contract's actual interface.
                </span>
              </div>
            )}
            {/* Current selectors */}
            {functions.length > 0 && (
              <div className="space-y-3">
                <p className="text-xs font-medium text-neutral-500">Allowed functions:</p>
                <div className="space-y-2">
                  {functions.map(rule => {
                    const label = getSelectorLabel(rule.selector);
                    const hasLabel = label !== rule.selector;
                    // Find ABI info for this function to show address-param checkboxes
                    const abiFunc = abiFunctions.find(
                      f => f.selector.toLowerCase() === rule.selector.toLowerCase()
                    );
                    const addressParams = abiFunc
                      ? abiFunc.inputs.filter(inp => inp.type === 'address')
                      : (COMMON_SELECTOR_PARAMS[rule.selector.toLowerCase()] || []);

                    return (
                      <div
                        key={rule.selector}
                        className="p-2 rounded-lg border border-primary-50 bg-neutral-50"
                      >
                        <div className="flex items-start gap-1.5">
                          <div className="flex flex-wrap items-center gap-1.5 min-w-0">
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-primary-50 text-primary border border-primary-50">
                              <code className="font-mono truncate max-w-[180px]">{rule.selector}</code>
                              {hasLabel && (
                                <span className="text-primary-300 truncate max-w-[120px]">({label})</span>
                              )}
                            </span>
                            {(rule.param_rules || []).map((pr, i) => {
                              const fnParamName = abiFunc?.inputs?.find(inp => inp.index === pr.index)?.name || `param[${pr.index}]`;
                              return (
                                <span key={pr.index} className="inline-flex items-center gap-1">
                                  {i > 0 && <span className="text-[10px] text-amber-600">AND</span>}
                                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-100 text-amber-800 border border-amber-200 font-medium whitespace-nowrap">
                                    {fnParamName}={pr.must_be}
                                  </span>
                                </span>
                              );
                            })}
                          </div>
                          <button
                            type="button"
                            onClick={() => handleRemoveSelector(rule.selector)}
                            className="shrink-0 hover:text-primary-700 text-primary-300 mt-1"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                        {/* Parameter constraints for address-type params */}
                        {addressParams.length > 0 && (
                          <div className="mt-2 ml-2 space-y-1">
                            {addressParams.map(param => {
                              const isChecked = (rule.param_rules || []).some(
                                pr => pr.index === param.index && pr.must_be === 'self'
                              );
                              return (
                                <label
                                  key={param.index}
                                  className="flex items-center gap-2 text-xs text-neutral-500 cursor-pointer"
                                >
                                  <input
                                    type="checkbox"
                                    checked={isChecked}
                                    onChange={e =>
                                      handleToggleParamRule(rule.selector, param.index, e.target.checked)
                                    }
                                    className="w-3.5 h-3.5 rounded text-primary focus:ring-primary"
                                  />
                                  <span>
                                    <code className="font-mono text-neutral-700">{param.name || `param[${param.index}]`}</code>
                                    {' '}must be caller's own address
                                  </span>
                                </label>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Add new selector */}
            <div className="flex gap-2">
              <input
                type="text"
                value={newSelector}
                onChange={e => setNewSelector(e.target.value)}
                placeholder="0x70a08231"
                className="flex-1 px-3 py-2 border border-neutral-200 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddSelector();
                  }
                }}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleAddSelector}
                className="gap-1"
              >
                <Plus className="w-4 h-4" />
                Add
              </Button>
            </div>

            {/* ABI Functions (if available) or Common selectors */}
            {abiFunctions.length > 0 ? (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <FileJson className="w-3.5 h-3.5 text-success" />
                  <p className="text-xs font-medium text-success-dark">Contract functions ({abiFunctions.length}):</p>
                </div>
                <div className="max-h-48 overflow-y-auto space-y-1 border border-neutral-200 rounded-lg p-2">
                  {abiFunctions.map(({ selector, name, stateMutability }) => {
                    const isView = stateMutability === 'view' || stateMutability === 'pure';
                    return (
                      <button
                        key={selector}
                        type="button"
                        onClick={() => handleAddCommonSelector(selector)}
                        disabled={hasFunctionSelector(selector)}
                        className="w-full flex items-center justify-between px-2 py-1.5 text-xs rounded hover:bg-neutral-100 hover:border-primary-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-left"
                      >
                        <span className="flex items-center gap-2 min-w-0">
                          <code className="font-mono text-neutral-500 truncate">{name}</code>
                          {isView && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-success-light text-success-dark font-medium">
                              view
                            </span>
                          )}
                        </span>
                        <code className="font-mono text-neutral-400 text-[10px] ml-2 flex-shrink-0">{selector}</code>
                      </button>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-xs font-medium text-neutral-500">Common selectors:</p>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(COMMON_SELECTORS).map(([selector, name]) => (
                    <button
                      key={selector}
                      type="button"
                      onClick={() => handleAddCommonSelector(selector)}
                      disabled={hasFunctionSelector(selector)}
                      className="px-2 py-1 text-xs rounded border border-neutral-200 hover:bg-neutral-100 hover:border-primary-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      <code className="font-mono text-neutral-500">{selector}</code>
                      <span className="ml-1 text-neutral-400">{name}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
      )}

      {/* Event Visibility */}
      {showEvents && (
        <div className="space-y-3">
        <label className="block text-sm font-medium text-neutral-700">
          Event Visibility
        </label>
        <p className="text-xs text-neutral-400">
          Restrict which contract event logs are visible to this group, or allow all events.
        </p>

        {/* Radio options */}
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 border border-neutral-200 rounded-lg cursor-pointer hover:bg-neutral-100 transition-colors">
            <input
              type="radio"
              name="eventMode"
              value="all"
              checked={eventMode === 'all'}
              onChange={() => setEventMode('all')}
              className="w-4 h-4 text-primary focus:ring-primary"
            />
            <div>
              <p className="text-sm font-medium text-neutral-900">All events visible</p>
              <p className="text-xs text-neutral-500">Group can see all event logs from this contract</p>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 border border-neutral-200 rounded-lg cursor-pointer hover:bg-neutral-100 transition-colors">
            <input
              type="radio"
              name="eventMode"
              value="specific"
              checked={eventMode === 'specific'}
              onChange={() => setEventMode('specific')}
              className="w-4 h-4 text-primary focus:ring-primary"
            />
            <div>
              <p className="text-sm font-medium text-neutral-900">Specific events only</p>
              <p className="text-xs text-neutral-500">Restrict to selected events (allowlist)</p>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 border border-neutral-200 rounded-lg cursor-pointer hover:bg-neutral-100 transition-colors">
            <input
              type="radio"
              name="eventMode"
              value="none"
              checked={eventMode === 'none'}
              onChange={() => setEventMode('none')}
              className="w-4 h-4 text-primary focus:ring-primary"
            />
            <div>
              <p className="text-sm font-medium text-neutral-900">No events visible</p>
              <p className="text-xs text-neutral-500">Block all event logs from this contract</p>
            </div>
          </label>
        </div>

        {/* Event picker (shown when specific mode) */}
        {eventMode === 'specific' && (
          <div className="space-y-3 pt-2">
            {/* Warning when no events selected */}
            {eventRules.length === 0 && (
              <p className="text-xs text-amber-600">Select at least one event from the list below, or switch to &quot;No events visible&quot;</p>
            )}
            {/* Selected event rules */}
            {eventRules.length > 0 && (
              <div className="space-y-3">
                <p className="text-xs font-medium text-neutral-500">Visible events:</p>
                <div className="space-y-2">
                  {eventRules.map(rule => {
                    // Find the event signature to show param info
                    const eventSig = availableEvents.find(
                      e => e.topic0.toLowerCase() === rule.topic0.toLowerCase()
                    );
                    const allParams = eventSig
                      ? eventSig.inputs.map((inp, idx) => ({ ...inp, index: idx }))
                      : [];

                    return (
                      <div
                        key={rule.topic0}
                        className="p-2 rounded-lg border border-primary-50 bg-neutral-50"
                      >
                        <div className="flex items-start gap-1.5">
                          <div className="flex flex-wrap items-center gap-1.5 min-w-0">
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-primary-50 text-primary border border-primary-50">
                              <Radio className="w-3 h-3 shrink-0" />
                              <span className="truncate max-w-[200px]">{rule.name}</span>
                            </span>
                            {eventSig && (
                              <span className="text-[10px] text-primary-300 truncate max-w-[180px]">({eventSig.signature})</span>
                            )}
                            {(rule.param_rules || []).map((pr, i) => {
                              const pName = eventSig?.inputs?.[pr.index]?.name || `param[${pr.index}]`;
                              return (
                                <span key={pr.index} className="inline-flex items-center gap-1">
                                  {i > 0 && <span className="text-[10px] text-amber-600">OR</span>}
                                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-100 text-amber-800 border border-amber-200 font-medium whitespace-nowrap">
                                    {pName}={pr.must_be}
                                  </span>
                                </span>
                              );
                            })}
                          </div>
                          <button
                            type="button"
                            onClick={() => handleRemoveEvent(rule.topic0)}
                            className="shrink-0 hover:text-primary-700 text-primary-300 mt-1"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                        {/* Parameter constraints */}
                        {allParams.length > 0 && (
                          <div className="mt-2 ml-2 space-y-2">
                            {allParams.map(param => {
                              const existingRule = (rule.param_rules || []).find(
                                pr => pr.index === param.index
                              );
                              const constraintMode = !existingRule
                                ? 'any'
                                : existingRule.must_be === 'self'
                                  ? 'self'
                                  : param.type === 'bool'
                                    ? (existingRule.must_be === '0x01' ? 'true' : 'false')
                                    : 'custom';
                              const customValue = existingRule && constraintMode === 'custom'
                                ? existingRule.must_be
                                : '';

                              return (
                                <EventParamConstraint
                                  key={param.index}
                                  param={param}
                                  constraintMode={constraintMode}
                                  customValue={customValue}
                                  onChange={(mustBe) => handleSetEventParamRule(rule.topic0, param.index, mustBe)}
                                />
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Available events from ABI */}
            {eventsLoading ? (
              <div className="flex items-center gap-2 py-2">
                <Loader2 className="w-4 h-4 animate-spin text-neutral-400" />
                <span className="text-xs text-neutral-500">Loading events from ABI...</span>
              </div>
            ) : availableEvents.length > 0 ? (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <FileJson className="w-3.5 h-3.5 text-success" />
                  <p className="text-xs font-medium text-success-dark">Contract events ({availableEvents.length}):</p>
                </div>
                <div className="max-h-48 overflow-y-auto space-y-1 border border-neutral-200 rounded-lg p-2">
                  {availableEvents.map(event => (
                    <button
                      key={event.topic0}
                      type="button"
                      onClick={() => handleAddEvent(event)}
                      disabled={hasEventTopic(event.topic0)}
                      className="w-full flex items-center justify-between px-2 py-1.5 text-xs rounded hover:bg-neutral-100 hover:border-primary-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-left"
                    >
                      <span className="flex items-center gap-1.5 min-w-0 overflow-hidden">
                        <Radio className="w-3 h-3 text-neutral-400 shrink-0" />
                        <code className="font-mono text-neutral-500 truncate">{event.name}</code>
                        <span className="text-neutral-400 text-[10px] truncate hidden sm:inline">({event.signature})</span>
                      </span>
                      <code className="font-mono text-neutral-400 text-[10px] ml-1 shrink-0">
                        {event.topic0.slice(0, 8)}…
                      </code>
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-warning-light border border-amber-200 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-amber-800 flex-shrink-0 mt-0.5" />
                <span className="text-amber-800 text-sm">
                  No ABI uploaded for this contract. Upload an ABI to configure event visibility rules.
                </span>
              </div>
            )}
          </div>
        )}
      </div>
      )}

      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      <div className="flex justify-end gap-3 pt-4 border-t border-neutral-200">
        <Button
          type="button"
          variant="outline"
          onClick={editMode === 'add' && step === 2 ? () => setStep(1) : onClose}
          disabled={saving}
          className="gap-2"
        >
          {editMode !== 'add' || step === 1 ? <X className="w-4 h-4" /> : null}
          {editMode === 'add' && step === 2 ? 'Back' : 'Cancel'}
        </Button>
        <Button
          type="submit"
          disabled={saving || !selectedGroupId || (!isEditing && availableGroups.length === 0) || (showEvents && eventMode === 'specific' && eventRules.length === 0) || (showFunctions && functionMode === 'specific' && functions.length === 0)}
          className="gap-2"
        >
          {saving ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : editMode === 'add' && step === 1 ? null : (
            <Save className="w-4 h-4" />
          )}
          {editMode === 'add' && step === 1 ? 'Next' : isEditing ? 'Save Changes' : 'Create Grant'}
        </Button>
      </div>
    </form>
  );
}
