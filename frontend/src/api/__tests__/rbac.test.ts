import { describe, it, expect } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { rbacApi } from '../rbac';
import {
  mockOrganization,
  mockGroup,
  mockUser,
  mockContract,
  mockGroupAccess,
  mockMembershipWithDetails,
  mockEffectivePermissions,
} from '@/test/mocks/handlers';

describe('RBAC API', () => {
  describe('Organizations', () => {
    describe('list', () => {
      it('should list all organizations', async () => {
        const response = await rbacApi.orgs.list();
        expect(response.data.data).toHaveLength(1);
        expect(response.data.data[0].slug).toBe(mockOrganization.slug);
      });

      it('should handle empty list', async () => {
        server.use(
          http.get('/api/v1/admin/orgs', () => {
            return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
          })
        );

        const response = await rbacApi.orgs.list();
        expect(response.data.data).toHaveLength(0);
      });
    });

    describe('get', () => {
      it('should get organization by ID', async () => {
        const response = await rbacApi.orgs.get('org-1');
        expect(response.data.id).toBe(mockOrganization.id);
        expect(response.data.name).toBe(mockOrganization.name);
      });

      it('should handle not found', async () => {
        await expect(rbacApi.orgs.get('nonexistent')).rejects.toThrow();
      });
    });

    describe('create', () => {
      it('should create a new organization', async () => {
        const response = await rbacApi.orgs.create({
          slug: 'new-org',
          name: 'New Organization',
        });

        expect(response.data.id).toBe('org-new');
        expect(response.data.slug).toBe('new-org');
        expect(response.data.name).toBe('New Organization');
      });
    });

    describe('update', () => {
      it('should update organization', async () => {
        const response = await rbacApi.orgs.update('org-1', {
          name: 'Updated Name',
        });

        expect(response.data.name).toBe('Updated Name');
      });
    });

    describe('delete', () => {
      it('should delete organization', async () => {
        await expect(rbacApi.orgs.delete('org-1')).resolves.not.toThrow();
      });
    });
  });

  describe('Groups', () => {
    describe('list', () => {
      it('should list groups for organization', async () => {
        const response = await rbacApi.groups.list('org-1');
        expect(response.data.data).toHaveLength(1);
        expect(response.data.data[0].group.name).toBe(mockGroup.name);
      });
    });

    describe('get', () => {
      it('should get group by ID', async () => {
        const response = await rbacApi.groups.get('org-1', 'group-1');
        expect(response.data.id).toBe(mockGroup.id);
        expect(response.data.path).toBe(mockGroup.path);
      });
    });

    describe('create', () => {
      it('should create a new group', async () => {
        const response = await rbacApi.groups.create('org-1', {
          slug: 'new-group',
          name: 'New Group',
          description: 'A new group',
        });

        expect(response.data.id).toBe('group-new');
        expect(response.data.slug).toBe('new-group');
      });
    });

    describe('update', () => {
      it('should update group', async () => {
        const response = await rbacApi.groups.update('org-1', 'group-1', {
          name: 'Updated Group',
        });

        expect(response.data.name).toBe('Updated Group');
      });
    });

    describe('delete', () => {
      it('should delete group', async () => {
        await expect(
          rbacApi.groups.delete('org-1', 'group-1')
        ).resolves.not.toThrow();
      });
    });

    describe('access', () => {
      it('should get group access settings', async () => {
        const response = await rbacApi.groups.getAccess('org-1', 'group-1');
        expect(response.data.allowed_methods).toEqual(
          mockGroupAccess.allowed_methods
        );
      });

      it('should set group access settings', async () => {
        const response = await rbacApi.groups.setAccess('org-1', 'group-1', {
          allowed_methods: ['eth_call', 'eth_sendTransaction'],
          claims: [],
        });

        expect(response.data.allowed_methods).toContain('eth_call');
        expect(response.data.allowed_methods).toContain('eth_sendTransaction');
      });
    });
  });

  describe('Users', () => {
    describe('list', () => {
      it('should list users with pagination', async () => {
        const response = await rbacApi.users.list({ limit: 10, offset: 0 });
        expect(response.data.data).toHaveLength(1);
        expect(response.data.data[0].external_id).toBe(mockUser.external_id);
      });
    });

    describe('get', () => {
      it('should get user by ID', async () => {
        const response = await rbacApi.users.get('user-1');
        expect(response.data.id).toBe(mockUser.id);
        expect(response.data.kyc).toBe(mockUser.kyc);
      });
    });

    describe('update', () => {
      it('should update user', async () => {
        const response = await rbacApi.users.update('user-1', {
          banned: true,
          note: 'Banned for testing',
        });

        expect(response.data.banned).toBe(true);
        expect(response.data.note).toBe('Banned for testing');
      });
    });

    describe('memberships', () => {
      it('should get user memberships', async () => {
        const response = await rbacApi.users.getMemberships('user-1');
        expect(response.data).toHaveLength(1);
        expect(response.data[0].group.id).toBe(
          mockMembershipWithDetails.group.id
        );
      });

      it('should create membership', async () => {
        const response = await rbacApi.users.createMembership('user-1', {
          group_id: 'group-1',
        });

        expect(response.data.id).toBe('membership-new');
        expect(response.data.group_id).toBe('group-1');
      });

      it('should delete membership', async () => {
        await expect(
          rbacApi.users.deleteMembership('user-1', 'membership-1')
        ).resolves.not.toThrow();
      });
    });

    describe('effective permissions', () => {
      it('should get effective permissions', async () => {
        const response = await rbacApi.users.getEffectivePermissions('user-1');
        expect(response.data.allowed_methods).toEqual(
          mockEffectivePermissions.allowed_methods
        );
        expect(response.data.claims).toEqual(mockEffectivePermissions.claims);
      });

      it('should get effective permissions for specific org', async () => {
        const response = await rbacApi.users.getEffectivePermissions(
          'user-1',
          'test-org'
        );
        expect(response.data.org_id).toBe(mockEffectivePermissions.org_id);
      });
    });
  });

  describe('Contracts', () => {
    describe('list', () => {
      it('should list contracts for organization', async () => {
        const response = await rbacApi.contracts.list('org-1');
        expect(response.data.data).toHaveLength(1);
        expect(response.data.data[0].address).toBe(mockContract.address);
      });
    });

    describe('create', () => {
      it('should create contract', async () => {
        const response = await rbacApi.contracts.create('org-1', {
          address: '0xnewcontract',
          name: 'New Contract',
        });

        expect(response.data.id).toBe('contract-new');
        expect(response.data.address).toBe('0xnewcontract');
      });
    });

    describe('update', () => {
      it('should update contract', async () => {
        const response = await rbacApi.contracts.update(
          'org-1',
          '0x1234567890123456789012345678901234567890',
          {
            name: 'Updated Contract',
          }
        );

        expect(response.data.name).toBe('Updated Contract');
      });
    });

    describe('delete', () => {
      it('should delete contract', async () => {
        await expect(
          rbacApi.contracts.delete(
            'org-1',
            '0x1234567890123456789012345678901234567890'
          )
        ).resolves.not.toThrow();
      });
    });
  });
});
