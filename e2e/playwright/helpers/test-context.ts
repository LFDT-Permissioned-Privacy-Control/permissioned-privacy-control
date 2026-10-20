import { randomUUID } from 'crypto';
import { APIRequestContext } from '@playwright/test';
import { createPolicy, deletePolicy, PolicyOptions } from './policy.js';
import { getJWTToken } from './auth.js';
import { RBACApiClient } from './rbac-api.js';
import { RBACTestFixture } from './rbac-fixtures.js';

/**
 * TestContext provides test isolation through unique DIDs.
 * Each test gets its own DID, preventing conflicts in parallel execution.
 */
export class TestContext {
  readonly testId: string;
  readonly userDID: string;
  private _accessToken: string | null = null;

  constructor() {
    this.testId = randomUUID().slice(0, 8);
    this.userDID = `did:privado:test_${this.testId}`;
  }

  /**
   * Create a policy for this test's user
   */
  async createPolicy(request: APIRequestContext, opts: PolicyOptions = {}): Promise<void> {
    await createPolicy(request, this.userDID, opts);
  }

  /**
   * Get a JWT token for this test's user
   */
  async getToken(request: APIRequestContext): Promise<string> {
    if (!this._accessToken) {
      this._accessToken = await getJWTToken(request, this.userDID);
    }
    return this._accessToken;
  }

  /**
   * Clean up policy for this test's user
   */
  async cleanup(request: APIRequestContext): Promise<void> {
    await deletePolicy(request, this.userDID);
    this._accessToken = null;
  }
}

/**
 * RBACTestContext provides test isolation for RBAC tests.
 * Wraps RBACApiClient and RBACTestFixture for convenient access.
 */
export class RBACTestContext {
  readonly testId: string;
  readonly fixture: RBACTestFixture;

  constructor(request: APIRequestContext) {
    this.fixture = new RBACTestFixture(request);
    this.testId = this.fixture.testId;
  }

  // Live view of the fixture's client. RD-1107: the fixture swaps this from
  // the super-admin client to an org-admin JWT on the first createOrg, so this
  // must read through rather than capture a stale reference.
  get rbac(): RBACApiClient {
    return this.fixture.rbac;
  }

  /**
   * Generate a unique slug for test isolation.
   */
  slug(base: string): string {
    return this.fixture.slug(base);
  }

  /**
   * Generate a unique DID for test isolation.
   */
  did(): string {
    return this.fixture.did();
  }

  /**
   * Generate a unique Ethereum address for test isolation.
   */
  contractAddress(): string {
    return this.fixture.contractAddress();
  }

  /**
   * Get a JWT token for a user DID.
   */
  async getToken(request: APIRequestContext, userDID: string): Promise<string> {
    return getJWTToken(request, userDID);
  }

  /**
   * Clean up all tracked resources.
   */
  async cleanup(): Promise<void> {
    await this.fixture.cleanup();
  }
}
