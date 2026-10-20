import { useState, useEffect, useRef, useCallback } from 'react';
import { Input } from '@/components/ui/input';
import { rbacApi } from '@/api/rbac';
import type { User } from '@/types/rbac';
import { Search, X, Loader2 } from 'lucide-react';

interface UserSearchInputProps {
  orgId: string;
  value: string;
  onChange: (userId: string) => void;
  disabled?: boolean;
}

function truncateDid(did: string, maxLen = 30): string {
  if (did.length <= maxLen) return did;
  return did.slice(0, maxLen) + '...';
}

export function UserSearchInput({ orgId, value, onChange, disabled }: UserSearchInputProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<User[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Load selected user details when value is set externally
  useEffect(() => {
    if (!value) {
      setSelectedUser(null);
      return;
    }

    // If we already have this user loaded, skip
    if (selectedUser?.id === value) return;

    rbacApi.users.get(value).then((res) => {
      setSelectedUser(res.data);
    }).catch(() => {
      // If user lookup fails, clear the selection
      setSelectedUser(null);
    });
  }, [value]); // eslint-disable-line react-hooks/exhaustive-deps

  const searchUsers = useCallback(async (searchQuery: string) => {
    if (!searchQuery.trim()) {
      setResults([]);
      setIsOpen(false);
      return;
    }

    setIsLoading(true);
    setIsOpen(true);
    try {
      const res = await rbacApi.users.list({
        search: searchQuery,
        org_id: orgId,
        limit: 10,
      });
      setResults(res.data.data || []);
    } catch {
      setResults([]);
    } finally {
      setIsLoading(false);
    }
  }, [orgId]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setQuery(val);

    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    debounceRef.current = setTimeout(() => {
      searchUsers(val);
    }, 300);
  };

  const handleSelect = (user: User) => {
    setSelectedUser(user);
    onChange(user.id);
    setIsOpen(false);
    setQuery('');
    setResults([]);
  };

  const handleClear = () => {
    setSelectedUser(null);
    onChange('');
    setQuery('');
    setResults([]);
    setIsOpen(false);
  };

  // Close dropdown on click outside
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Close dropdown on Escape
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setIsOpen(false);
    }
  };

  // Cleanup debounce on unmount
  useEffect(() => {
    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, []);

  // Selected state: show DID with clear button
  if (selectedUser) {
    return (
      <div
        className="flex items-center h-10 rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm text-neutral-700"
      >
        <span className="flex-1 truncate" title={selectedUser.external_id}>
          {truncateDid(selectedUser.external_id)}
        </span>
        {!disabled && (
          <button
            type="button"
            onClick={handleClear}
            className="ml-2 text-neutral-400 hover:text-neutral-700 transition-colors"
            aria-label="Clear selection"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    );
  }

  // Search state
  return (
    <div ref={containerRef} className="relative" onKeyDown={handleKeyDown}>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-400" />
        <Input
          value={query}
          onChange={handleInputChange}
          placeholder="Search users by DID..."
          disabled={disabled}
          className="pl-9"
        />
      </div>

      {isOpen && (
        <div className="absolute z-10 mt-1 w-full bg-white border border-neutral-200 rounded-lg shadow-md max-h-60 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center py-4 text-neutral-500">
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
              <span className="text-sm">Searching...</span>
            </div>
          ) : results.length === 0 ? (
            <div className="py-4 text-center text-sm text-neutral-500">
              No users found
            </div>
          ) : (
            results.map((user) => (
              <button
                key={user.id}
                type="button"
                onClick={() => handleSelect(user)}
                className="w-full text-left px-3 py-2 text-sm text-neutral-700 hover:bg-neutral-100 transition-colors cursor-pointer"
              >
                {truncateDid(user.external_id)}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}
