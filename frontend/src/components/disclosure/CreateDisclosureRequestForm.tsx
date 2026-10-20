import { useState, useEffect, useRef } from 'react';
import { Plus, X, Info, Search, User, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import type { CreateDisclosureRequestInput, DisclosureScope } from '@/types/disclosure';
import { ALL_SCOPES, SCOPE_LABELS, SCOPE_DESCRIPTIONS, ALL_DISCLOSURE_LEVELS, DISCLOSURE_LEVEL_LABELS, DISCLOSURE_LEVEL_DESCRIPTIONS } from '@/types/disclosure';
import { rbacApi } from '@/api/rbac';
import type { User as RbacUser } from '@/types/rbac';

interface CreateDisclosureRequestFormProps {
  onSubmit: (input: CreateDisclosureRequestInput) => Promise<void>;
  onCancel?: () => void;
  isLoading?: boolean;
}

export function CreateDisclosureRequestForm({
  onSubmit,
  onCancel,
  isLoading = false,
}: CreateDisclosureRequestFormProps) {
  const [formData, setFormData] = useState<Partial<CreateDisclosureRequestInput>>({
    requester_name: '',
    requester_org: '',
    requester_did: '',
    purpose: '',
    scope: [],
    disclosure_level: 'pseudonymous', // Default to pseudonymous for privacy
    user_external_id: '',
    request_reference: '',
    legal_basis: '',
    valid_from: '',
    valid_until: '',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  // User dropdown state (for target user)
  const [users, setUsers] = useState<RbacUser[]>([]);
  const [usersLoading, setUsersLoading] = useState(true);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [userSearch, setUserSearch] = useState('');
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [selectedUser, setSelectedUser] = useState<RbacUser | null>(null);

  // Requester dropdown state (for auditor DID)
  const [requesterSearch, setRequesterSearch] = useState('');
  const [showRequesterDropdown, setShowRequesterDropdown] = useState(false);
  const [selectedRequester, setSelectedRequester] = useState<RbacUser | null>(null);

  // Fetch users on mount
  useEffect(() => {
    const fetchUsers = async () => {
      try {
        setUsersLoading(true);
        const response = await rbacApi.users.list({ limit: 100 });
        setUsers(response.data?.data || []);
        setUsersError(null);
      } catch (err) {
        setUsersError('Failed to load users');
        console.error('Failed to fetch users:', err);
      } finally {
        setUsersLoading(false);
      }
    };
    fetchUsers();
  }, []);

  // Filter users based on search (for target user)
  const filteredUsers = users.filter((user) => {
    const search = userSearch.toLowerCase();
    return (
      user.external_id.toLowerCase().includes(search) ||
      user.id.toLowerCase().includes(search) ||
      (user.note && user.note.toLowerCase().includes(search))
    );
  });

  // Filter users based on search (for requester/auditor)
  const filteredRequesters = users.filter((user) => {
    const search = requesterSearch.toLowerCase();
    return (
      user.external_id.toLowerCase().includes(search) ||
      user.id.toLowerCase().includes(search) ||
      (user.note && user.note.toLowerCase().includes(search))
    );
  });

  // Handle user selection
  const handleSelectUser = (user: RbacUser) => {
    setSelectedUser(user);
    setFormData((prev) => ({ ...prev, user_external_id: user.id }));
    setUserSearch('');
    setShowUserDropdown(false);
    if (errors.user_external_id) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next.user_external_id;
        return next;
      });
    }
  };

  // Clear user selection
  const handleClearUser = () => {
    setSelectedUser(null);
    setFormData((prev) => ({ ...prev, user_external_id: '' }));
  };

  // Handle requester selection
  const handleSelectRequester = (user: RbacUser) => {
    setSelectedRequester(user);
    setFormData((prev) => ({ ...prev, requester_did: user.external_id }));
    setRequesterSearch('');
    setShowRequesterDropdown(false);
  };

  // Clear requester selection
  const handleClearRequester = () => {
    setSelectedRequester(null);
    setFormData((prev) => ({ ...prev, requester_did: '' }));
  };

  // Click outside handler for dropdowns
  const dropdownRef = useRef<HTMLDivElement>(null);
  const requesterDropdownRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowUserDropdown(false);
      }
      if (requesterDropdownRef.current && !requesterDropdownRef.current.contains(event.target as Node)) {
        setShowRequesterDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const updateField = <K extends keyof CreateDisclosureRequestInput>(
    field: K,
    value: CreateDisclosureRequestInput[K]
  ) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    // Clear error when field is updated
    if (errors[field]) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
    }
  };

  const toggleScope = (scope: DisclosureScope) => {
    const currentScopes = formData.scope || [];
    if (currentScopes.includes(scope)) {
      updateField('scope', currentScopes.filter((s) => s !== scope));
      return;
    }
    // full_disclosure is a superset of the narrow scopes, so it is mutually
    // exclusive with them (RD-1072): selecting it clears the narrow scopes,
    // and selecting a narrow scope clears full_disclosure. This keeps the
    // requested-scope record unambiguous on what is a compliance artifact.
    if (scope === 'full_disclosure') {
      updateField('scope', ['full_disclosure']);
    } else {
      updateField('scope', [
        ...currentScopes.filter((s) => s !== 'full_disclosure'),
        scope,
      ]);
    }
  };

  const validate = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.user_external_id?.trim()) {
      newErrors.user_external_id = 'User ID (DID) is required';
    }
    if (!formData.requester_name?.trim()) {
      newErrors.requester_name = 'Requester name is required';
    }
    if (!formData.purpose?.trim()) {
      newErrors.purpose = 'Purpose is required';
    }
    if (!formData.scope?.length) {
      newErrors.scope = 'At least one scope must be selected';
    }
    if (!formData.disclosure_level) {
      newErrors.disclosure_level = 'Disclosure level is required';
    }

    // Validate dates if provided
    if (formData.valid_from && formData.valid_until) {
      const from = new Date(formData.valid_from);
      const until = new Date(formData.valid_until);
      if (from >= until) {
        newErrors.valid_until = 'End date must be after start date';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    const input: CreateDisclosureRequestInput = {
      user_external_id: formData.user_external_id!.trim(),
      requester_name: formData.requester_name!.trim(),
      purpose: formData.purpose!.trim(),
      scope: formData.scope!,
      disclosure_level: formData.disclosure_level!,
    };

    // Add optional fields if provided
    if (formData.requester_org?.trim()) {
      input.requester_org = formData.requester_org.trim();
    }
    if (formData.requester_did?.trim()) {
      input.requester_did = formData.requester_did.trim();
    }
    if (formData.request_reference?.trim()) {
      input.request_reference = formData.request_reference.trim();
    }
    if (formData.legal_basis?.trim()) {
      input.legal_basis = formData.legal_basis.trim();
    }
    if (formData.valid_from) {
      input.valid_from = new Date(formData.valid_from).toISOString();
    }
    if (formData.valid_until) {
      input.valid_until = new Date(formData.valid_until).toISOString();
    }

    await onSubmit(input);
  };

  return (
    <Card variant="default">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Plus className="w-5 h-5 text-primary" />
          Create Disclosure Request
        </CardTitle>
        <CardDescription>
          Request access to a user's activity data for compliance or audit purposes.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target User */}
          <div className="space-y-2">
            <label className="text-sm text-neutral-500">
              Target User <span className="text-error-dark">*</span>
            </label>

            {/* Selected User Display */}
            {selectedUser ? (
              <div className="flex items-center gap-2 p-3 rounded-lg border border-primary bg-primary-50">
                <User className="w-5 h-5 text-primary flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-neutral-900 font-medium truncate">
                    {selectedUser.external_id}
                  </p>
                  <p className="text-xs text-neutral-400">
                    ID: {selectedUser.id}
                    {selectedUser.kyc && (
                      <Badge variant="success" className="ml-2 text-xs">KYC</Badge>
                    )}
                    {selectedUser.banned && (
                      <Badge variant="destructive" className="ml-2 text-xs">Banned</Badge>
                    )}
                  </p>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleClearUser}
                  disabled={isLoading}
                  className="flex-shrink-0"
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            ) : (
              /* User Search/Dropdown */
              <div className="relative" ref={dropdownRef}>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" />
                  <Input
                    value={userSearch}
                    onChange={(e) => {
                      setUserSearch(e.target.value);
                      setShowUserDropdown(true);
                    }}
                    onFocus={() => setShowUserDropdown(true)}
                    placeholder="Search users by DID or ID..."
                    className="pl-10"
                    disabled={isLoading || usersLoading}
                  />
                  {usersLoading && (
                    <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400 animate-spin" />
                  )}
                </div>

                {/* Dropdown */}
                {showUserDropdown && !usersLoading && (
                  <div className="absolute z-50 w-full mt-1 max-h-60 overflow-auto rounded-lg border border-neutral-200 bg-white shadow-lg">
                    {usersError ? (
                      <div className="p-3 text-sm text-error-dark">{usersError}</div>
                    ) : filteredUsers.length === 0 ? (
                      <div className="p-3 text-sm text-neutral-400">
                        {userSearch ? 'No users match your search' : 'No users found'}
                      </div>
                    ) : (
                      filteredUsers.map((user) => (
                        <button
                          key={user.id}
                          type="button"
                          onClick={() => handleSelectUser(user)}
                          className="w-full p-3 text-left hover:bg-primary-50 transition-colors border-b border-neutral-200 last:border-b-0"
                        >
                          <div className="flex items-center gap-2">
                            <User className="w-4 h-4 text-neutral-400 flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-neutral-900 truncate">
                                {user.external_id}
                              </p>
                              <p className="text-xs text-neutral-400 flex items-center gap-2">
                                <span className="truncate">{user.id}</span>
                                {user.kyc && (
                                  <Badge variant="success" className="text-xs">KYC</Badge>
                                )}
                                {user.banned && (
                                  <Badge variant="destructive" className="text-xs">Banned</Badge>
                                )}
                              </p>
                            </div>
                          </div>
                        </button>
                      ))
                    )}
                  </div>
                )}
              </div>
            )}
            {errors.user_external_id && (
              <p className="text-error-dark text-xs">{errors.user_external_id}</p>
            )}
          </div>

          {/* Requester Info */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm text-neutral-500">
                Requester Name <span className="text-error-dark">*</span>
              </label>
              <Input
                value={formData.requester_name || ''}
                onChange={(e) => updateField('requester_name', e.target.value)}
                placeholder="e.g., SEC Compliance Officer"
                disabled={isLoading}
              />
              {errors.requester_name && (
                <p className="text-error-dark text-xs">{errors.requester_name}</p>
              )}
            </div>
            <div className="space-y-2">
              <label className="text-sm text-neutral-500">Organization</label>
              <Input
                value={formData.requester_org || ''}
                onChange={(e) => updateField('requester_org', e.target.value)}
                placeholder="e.g., Securities and Exchange Commission"
                disabled={isLoading}
              />
            </div>
          </div>

          {/* Requester DID - for block explorer integration */}
          <div className="space-y-2">
            <label className="text-sm text-neutral-500">
              Auditor (Who Gets Access)
            </label>
            <p className="text-xs text-neutral-400 mb-2">
              Select the auditor who will access data via the block explorer.
            </p>

            {/* Selected Requester Display */}
            {selectedRequester ? (
              <div className="flex items-center gap-2 p-3 rounded-lg border border-success-dark bg-success-light">
                <User className="w-5 h-5 text-success-dark flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-neutral-900 font-medium truncate">
                    {selectedRequester.external_id}
                  </p>
                  <p className="text-xs text-neutral-400">
                    ID: {selectedRequester.id}
                  </p>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleClearRequester}
                  disabled={isLoading}
                  className="flex-shrink-0"
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            ) : (
              /* Requester Search/Dropdown */
              <div className="relative" ref={requesterDropdownRef}>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" />
                  <Input
                    value={requesterSearch}
                    onChange={(e) => {
                      setRequesterSearch(e.target.value);
                      setShowRequesterDropdown(true);
                    }}
                    onFocus={() => setShowRequesterDropdown(true)}
                    placeholder="Search auditors by DID..."
                    className="pl-10"
                    disabled={isLoading || usersLoading}
                  />
                  {usersLoading && (
                    <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400 animate-spin" />
                  )}
                </div>

                {/* Dropdown */}
                {showRequesterDropdown && !usersLoading && (
                  <div className="absolute z-50 w-full mt-1 max-h-60 overflow-auto rounded-lg border border-neutral-200 bg-white shadow-lg">
                    {usersError ? (
                      <div className="p-3 text-sm text-error-dark">{usersError}</div>
                    ) : filteredRequesters.length === 0 ? (
                      <div className="p-3 text-sm text-neutral-400">
                        {requesterSearch ? 'No users match your search' : 'No users found'}
                      </div>
                    ) : (
                      filteredRequesters.map((user) => (
                        <button
                          key={user.id}
                          type="button"
                          onClick={() => handleSelectRequester(user)}
                          className="w-full p-3 text-left hover:bg-primary-50 transition-colors border-b border-neutral-200 last:border-b-0"
                        >
                          <div className="flex items-center gap-2">
                            <User className="w-4 h-4 text-neutral-400 flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-neutral-900 truncate">
                                {user.external_id}
                              </p>
                              <p className="text-xs text-neutral-400 truncate">{user.id}</p>
                            </div>
                          </div>
                        </button>
                      ))
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Purpose */}
          <div className="space-y-2">
            <label className="text-sm text-neutral-500">
              Purpose <span className="text-error-dark">*</span>
            </label>
            <Textarea
              value={formData.purpose || ''}
              onChange={(e) => updateField('purpose', e.target.value)}
              placeholder="Describe why you need access to this user's data..."
              rows={3}
              disabled={isLoading}
            />
            {errors.purpose && (
              <p className="text-error-dark text-xs">{errors.purpose}</p>
            )}
          </div>

          {/* Legal Basis */}
          <div className="space-y-2">
            <label className="text-sm text-neutral-500">Legal Basis</label>
            <Input
              value={formData.legal_basis || ''}
              onChange={(e) => updateField('legal_basis', e.target.value)}
              placeholder="e.g., Regulation XYZ, Court Order #12345"
              disabled={isLoading}
            />
          </div>

          {/* Reference */}
          <div className="space-y-2">
            <label className="text-sm text-neutral-500">Request Reference</label>
            <Input
              value={formData.request_reference || ''}
              onChange={(e) => updateField('request_reference', e.target.value)}
              placeholder="e.g., Case #2024-001"
              disabled={isLoading}
            />
          </div>

          {/* Scope Selection */}
          <div className="space-y-3">
            <label className="text-sm text-neutral-500">
              Requested Data Scope <span className="text-error-dark">*</span>
            </label>
            <div className="space-y-2">
              {ALL_SCOPES.map((scope) => {
                const isSelected = formData.scope?.includes(scope);
                return (
                  <button
                    key={scope}
                    type="button"
                    onClick={() => toggleScope(scope)}
                    disabled={isLoading}
                    className={`w-full p-3 rounded-lg border text-left transition-all ${
                      isSelected
                        ? 'border-primary bg-primary-50'
                        : 'border-neutral-200 bg-white hover:bg-neutral-100'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className={`w-5 h-5 rounded border flex items-center justify-center mt-0.5 ${
                          isSelected
                            ? 'border-primary bg-primary'
                            : 'border-neutral-300'
                        }`}
                      >
                        {isSelected && (
                          <svg
                            className="w-3 h-3 text-white"
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={3}
                              d="M5 13l4 4L19 7"
                            />
                          </svg>
                        )}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-neutral-900 font-medium">
                            {SCOPE_LABELS[scope]}
                          </span>
                          {scope === 'full_disclosure' && (
                            <Badge variant="warning" className="text-xs">
                              Full Access
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-neutral-400 mt-0.5">
                          {SCOPE_DESCRIPTIONS[scope]}
                        </p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
            <p className="text-xs text-neutral-400">
              Full Disclosure already covers activity logs and transaction history, so it can't be combined with them.
            </p>
            {errors.scope && (
              <p className="text-error-dark text-xs">{errors.scope}</p>
            )}
          </div>

          {/* Disclosure Level Selection */}
          <div className="space-y-3">
            <label className="text-sm text-neutral-500">
              Disclosure Level <span className="text-error-dark">*</span>
            </label>
            <p className="text-xs text-neutral-400">
              Controls how much address detail is revealed to the auditor
            </p>
            <div className="space-y-2">
              {ALL_DISCLOSURE_LEVELS.map((level) => {
                const isSelected = formData.disclosure_level === level;
                return (
                  <button
                    key={level}
                    type="button"
                    onClick={() => updateField('disclosure_level', level)}
                    disabled={isLoading}
                    className={`w-full p-3 rounded-lg border text-left transition-all ${
                      isSelected
                        ? 'border-primary bg-primary-50'
                        : 'border-neutral-200 bg-white hover:bg-neutral-100'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className={`w-5 h-5 rounded-full border flex items-center justify-center mt-0.5 ${
                          isSelected
                            ? 'border-primary bg-primary'
                            : 'border-neutral-300'
                        }`}
                      >
                        {isSelected && (
                          <div className="w-2 h-2 rounded-full bg-white" />
                        )}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-neutral-900 font-medium">
                            {DISCLOSURE_LEVEL_LABELS[level]}
                          </span>
                          {level === 'full' && (
                            <Badge variant="destructive" className="text-xs">
                              Sensitive
                            </Badge>
                          )}
                          {level === 'pseudonymous' && (
                            <Badge variant="warning" className="text-xs">
                              Recommended
                            </Badge>
                          )}
                          {level === 'redacted' && (
                            <Badge variant="success" className="text-xs">
                              Most Private
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-neutral-400 mt-0.5">
                          {DISCLOSURE_LEVEL_DESCRIPTIONS[level]}
                        </p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
            {errors.disclosure_level && (
              <p className="text-error-dark text-xs">{errors.disclosure_level}</p>
            )}
          </div>

          {/* Validity Period */}
          <div className="space-y-3">
            <label className="text-sm text-neutral-500 flex items-center gap-2">
              <span>Validity Period</span>
              <Info className="w-4 h-4 text-neutral-400" />
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-xs text-neutral-400">Start Date (optional)</label>
                <Input
                  type="datetime-local"
                  value={formData.valid_from || ''}
                  onChange={(e) => updateField('valid_from', e.target.value)}
                  disabled={isLoading}
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs text-neutral-400">End Date (optional)</label>
                <Input
                  type="datetime-local"
                  value={formData.valid_until || ''}
                  onChange={(e) => updateField('valid_until', e.target.value)}
                  disabled={isLoading}
                />
                {errors.valid_until && (
                  <p className="text-error-dark text-xs">{errors.valid_until}</p>
                )}
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-end gap-3 pt-4 border-t border-neutral-200">
            {onCancel && (
              <Button
                type="button"
                variant="outline"
                onClick={onCancel}
                disabled={isLoading}
              >
                <X className="w-4 h-4 mr-2" />
                Cancel
              </Button>
            )}
            <Button type="submit" variant="default" disabled={isLoading}>
              <Plus className="w-4 h-4 mr-2" />
              {isLoading ? 'Creating...' : 'Create Request'}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

export default CreateDisclosureRequestForm;
