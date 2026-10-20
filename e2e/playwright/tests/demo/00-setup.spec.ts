import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test, expect, type APIRequestContext } from '@playwright/test';
import { getJWTToken } from '../../helpers/auth';
import { RBACApiClient, fns, type Group, type User } from '../../helpers/rbac-api';
import {
  anvilRpc,
  encodeBytesData,
  encodeAddressWord,
  encodeUintWord,
  linkAddress,
  proxyRpc,
  waitForExplorerTransaction,
  waitForReceipt,
} from '../../helpers/demo/api';
import { writeDemoManifest } from '../../helpers/demo/state';
import type {
  DemoDisclosureGrant,
  DemoPersona,
  DemoScenarioManifest,
  PersonaName,
} from '../../helpers/demo/types';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
const ARTIFACT_DIR = process.env.CONTRACT_ARTIFACT_DIR || '../../contracts/out';
const COUNT = '0x06661abd';
const INCREMENT = '0xd09de08a';
const TRANSFER = '0xa9059cbb';
const MINT = '0x40c10f19';
const FORWARD = '0x6fadcf72';
const BALANCE_OF = '0x70a08231';
const READ_METHODS = [
  'eth_call',
  'eth_getBalance',
  'eth_getBlockByNumber',
  'eth_getBlockByHash',
  'eth_getTransactionByHash',
  'eth_getTransactionReceipt',
  'eth_getLogs',
];
const WRITE_METHODS = [...READ_METHODS, 'eth_sendTransaction'];

const ACCOUNT_BY_PERSONA: Record<PersonaName, number> = {
  admin: 0,
  reader: 1,
  writer: 2,
  target: 3,
  observer: 4,
  fullAuditor: 5,
  pseudonymousAuditor: 6,
  redactedAuditor: 7,
  outsider: 8,
  orgBMember: 9,
};

interface FoundryArtifact {
  abi: unknown[];
  bytecode: { object: string };
}

async function requireResponse(response: Awaited<ReturnType<APIRequestContext['post']>>, action: string) {
  if (!response.ok()) {
    throw new Error(`${action} failed (${response.status()}): ${await response.text()}`);
  }
  return response;
}

async function deploy(
  request: APIRequestContext,
  from: string,
  artifactName: string,
): Promise<{ address: string; hash: string; abi: string }> {
  const raw = await readFile(`${ARTIFACT_DIR}/${artifactName}.sol/${artifactName}.json`, 'utf8');
  const artifact = JSON.parse(raw) as FoundryArtifact;
  const hash = await anvilRpc<string>(request, 'eth_sendTransaction', [{
    from,
    data: artifact.bytecode.object,
    gas: '0x7a1200',
  }]);
  const receipt = await waitForReceipt(request, hash);
  if (!receipt.contractAddress) throw new Error(`${artifactName} deployment returned no address`);
  return { address: receipt.contractAddress.toLowerCase(), hash, abi: JSON.stringify(artifact.abi) };
}

async function adminPut(
  request: APIRequestContext,
  token: string,
  path: string,
  data: unknown,
): Promise<unknown> {
  const response = await request.put(`${PROXY_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    data,
  });
  await requireResponse(response, `PUT ${path}`);
  return response.json();
}

function encodeForwardCall(target: string, data: string): string {
  return `${FORWARD}${encodeAddressWord(target)}${encodeUintWord(64n)}${encodeBytesData(data)}`;
}

function encodeMintCall(to: string, amount: bigint): string {
  return `${MINT}${encodeAddressWord(to)}${encodeUintWord(amount)}`;
}

async function createDisclosure(
  request: APIRequestContext,
  adminToken: string,
  targetToken: string,
  orgId: string,
  target: User,
  requester: DemoPersona,
  requesterKey: 'fullAuditor' | 'pseudonymousAuditor' | 'redactedAuditor',
  level: DemoDisclosureGrant['level'],
): Promise<DemoDisclosureGrant> {
  const create = await request.post(`${PROXY_URL}/api/v1/admin/disclosure/requests`, {
    headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    data: {
      requester_user_id: requester.id,
      requester_did: requester.did,
      target_user_id: target.id,
      org_id: orgId,
      scope: {
        disclosure_level: level,
        methods: ['transaction_history', 'activity_logs'],
      },
      reason: `Demo acceptance ${level} disclosure`,
      legal_basis: 'E2E test fixture',
      expires_in_hours: 4,
    },
  });
  await requireResponse(create, `Create ${level} disclosure`);
  const created = await create.json() as { id: string };

  const approve = await request.post(
    `${PROXY_URL}/api/v1/me/disclosure/requests/${created.id}/approve`,
    {
      headers: { Authorization: `Bearer ${targetToken}`, 'Content-Type': 'application/json' },
      data: { grant_duration_hours: 4, reason: 'Approved by demo target' },
    },
  );
  await requireResponse(approve, `Approve ${level} disclosure`);
  const approved = await approve.json() as { grant: { id: string } };
  return { requestId: created.id, grantId: approved.grant.id, level, requester: requesterKey };
}

test('build the real demo acceptance scenario', async ({ request }) => {
  test.setTimeout(180_000);
  const runId = randomUUID().slice(0, 8);
  const sa = new RBACApiClient(request);
  const accounts = (await anvilRpc<string[]>(request, 'eth_accounts')).map(a => a.toLowerCase());
  expect(accounts.length).toBeGreaterThanOrEqual(10);

  const adminDid = `did:privado:demo:${runId}:admin`;
  await getJWTToken(request, adminDid);
  const adminUser = await sa.findUserByExternalId(adminDid);
  if (!adminUser) throw new Error('Admin user was not created by mock authentication');
  await sa.updateUser(adminUser.id, { kyc: true, note: `demo-e2e:${runId}` });

  const orgA = await sa.createOrganization({ slug: `demo-a-${runId}`, name: `Demo Acceptance A ${runId}` });
  const orgB = await sa.createOrganization({ slug: `demo-b-${runId}`, name: `Demo Acceptance B ${runId}` });
  const adminGroups: Record<'a' | 'b', Group> = {
    a: await sa.createGroup(orgA.id, { slug: `admin-${runId}`, name: 'Demo Org A Admin', is_org_admin: true }),
    b: await sa.createGroup(orgB.id, { slug: `admin-${runId}`, name: 'Demo Org B Admin', is_org_admin: true }),
  };
  await sa.createMembership(adminUser.id, { group_id: adminGroups.a.id });
  await sa.createMembership(adminUser.id, { group_id: adminGroups.b.id });
  const adminToken = await getJWTToken(request, adminDid);
  await linkAddress(request, adminToken, accounts[0]);
  const orgAdmin = sa.asOrgAdmin(adminToken);

  const group = async (slug: string, methods: string[]) => {
    const created = await orgAdmin.createGroup(orgA.id, { slug: `${slug}-${runId}`, name: `Demo ${slug}` });
    await orgAdmin.setGroupAccess(orgA.id, created.id, { allowed_methods: methods, claims: [] });
    return created;
  };
  const groups = {
    reader: await group('reader', READ_METHODS),
    writer: await group('writer', WRITE_METHODS),
    observer: await group('observer', READ_METHODS),
    auditor: await group('auditor', READ_METHODS),
    outsider: await group('outsider', READ_METHODS),
  };
  const orgBGroup = await orgAdmin.createGroup(orgB.id, { slug: `member-${runId}`, name: 'Demo Org B Member' });
  await orgAdmin.setGroupAccess(orgB.id, orgBGroup.id, { allowed_methods: READ_METHODS, claims: [] });

  const personaGroups: Record<Exclude<PersonaName, 'admin'>, { id: string; orgId: string }> = {
    reader: { id: groups.reader.id, orgId: orgA.id },
    writer: { id: groups.writer.id, orgId: orgA.id },
    target: { id: groups.writer.id, orgId: orgA.id },
    observer: { id: groups.observer.id, orgId: orgA.id },
    fullAuditor: { id: groups.auditor.id, orgId: orgA.id },
    pseudonymousAuditor: { id: groups.auditor.id, orgId: orgA.id },
    redactedAuditor: { id: groups.auditor.id, orgId: orgA.id },
    outsider: { id: groups.outsider.id, orgId: orgA.id },
    orgBMember: { id: orgBGroup.id, orgId: orgB.id },
  };
  const personas = {} as Record<PersonaName, DemoPersona>;
  personas.admin = {
    id: adminUser.id, did: adminDid, address: accounts[0], token: adminToken,
    groupId: adminGroups.a.id, orgId: orgA.id,
  };
  for (const name of Object.keys(personaGroups) as Array<Exclude<PersonaName, 'admin'>>) {
    const did = `did:privado:demo:${runId}:${name}`;
    const token = await getJWTToken(request, did);
    const user = await sa.findUserByExternalId(did);
    if (!user) throw new Error(`User ${name} was not created`);
    await sa.updateUser(user.id, { kyc: true, note: `demo-e2e:${runId}:${name}` });
    await orgAdmin.createMembership(user.id, { group_id: personaGroups[name].id });
    const address = accounts[ACCOUNT_BY_PERSONA[name]];
    await linkAddress(request, token, address);
    personas[name] = {
      id: user.id, did, address, token, groupId: personaGroups[name].id, orgId: personaGroups[name].orgId,
    };
  }

  const counter = await deploy(request, accounts[0], 'Counter');
  const token = await deploy(request, accounts[0], 'DemoERC20');
  const forwarder = await deploy(request, accounts[0], 'Forwarder');
  await orgAdmin.createContract(orgA.id, { address: counter.address, name: 'Demo Counter' });
  await orgAdmin.updateContractABI(orgA.id, counter.address, counter.abi);
  await orgAdmin.createContract(orgA.id, {
    address: token.address,
    name: 'Demo Token',
    metadata: { token_type: 'ERC20', symbol: 'DEMO', decimals: 18 },
  });
  await orgAdmin.updateContractABI(orgA.id, token.address, token.abi);
  await orgAdmin.createContract(orgA.id, { address: forwarder.address, name: 'Demo Forwarder' });
  await orgAdmin.updateContractABI(orgA.id, forwarder.address, forwarder.abi);

  const counterEvents = await orgAdmin.listContractEvents(orgA.id, counter.address);
  const countIncremented = counterEvents.find(event => event.name === 'CountIncremented');
  if (!countIncremented) throw new Error('Counter ABI did not expose CountIncremented');
  const tokenEvents = await orgAdmin.listContractEvents(orgA.id, token.address);
  const transferEvent = tokenEvents.find(event => event.name === 'Transfer');
  if (!transferEvent) throw new Error('Token ABI did not expose Transfer');
  const forwarderEvents = await orgAdmin.listContractEvents(orgA.id, forwarder.address);
  const forwardedCallEvent = forwarderEvents.find(event => event.name === 'ForwardedCall');
  if (!forwardedCallEvent) throw new Error('Forwarder ABI did not expose ForwardedCall');

  await orgAdmin.createContractGrant(orgA.id, counter.address, {
    group_id: groups.reader.id, functions: fns(COUNT), event_rules: [],
  });
  await orgAdmin.createContractGrant(orgA.id, counter.address, {
    group_id: groups.writer.id, functions: fns(COUNT, INCREMENT),
    event_rules: [{ topic0: countIncremented.topic0, name: countIncremented.name }],
  });
  await orgAdmin.createContractGrant(orgA.id, counter.address, {
    group_id: groups.observer.id, functions: fns(COUNT), event_rules: [],
  });
  await orgAdmin.createContractGrant(orgA.id, token.address, {
    group_id: groups.writer.id, functions: fns(TRANSFER, BALANCE_OF),
    event_rules: [{ topic0: transferEvent.topic0, name: transferEvent.name }],
  });
  await orgAdmin.createContractGrant(orgA.id, token.address, {
    group_id: adminGroups.a.id, functions: fns(MINT, BALANCE_OF),
    event_rules: [{ topic0: transferEvent.topic0, name: transferEvent.name }],
  });
  await orgAdmin.createContractGrant(orgA.id, forwarder.address, {
    group_id: groups.writer.id, functions: fns(FORWARD),
    event_rules: [{ topic0: forwardedCallEvent.topic0, name: forwardedCallEvent.name }],
  });
  await adminPut(
    request,
    adminToken,
    `/api/v1/admin/orgs/${orgA.id}/contracts/${counter.address}/visibleto-unlock`,
    { allow_visibleto_unlock: true },
  );

  const seedAmount = 1_000n * 10n ** 18n;
  const seedHash = await anvilRpc<string>(request, 'eth_sendTransaction', [{
    from: accounts[0], to: token.address,
    data: `${TRANSFER}${encodeAddressWord(personas.writer.address)}${encodeUintWord(seedAmount)}`,
    gas: '0x30d40',
  }]);
  await waitForReceipt(request, seedHash);

  const mintAmount = 250n * 10n ** 18n;
  const mintHash = await anvilRpc<string>(request, 'eth_sendTransaction', [{
    from: accounts[0], to: token.address,
    data: encodeMintCall(personas.writer.address, mintAmount),
    gas: '0x30d40',
  }]);
  const mintReceipt = await waitForReceipt(request, mintHash);

  const writerIncrement = await proxyRpc<string>(
    request,
    personas.writer.token,
    orgA.id,
    'eth_sendTransaction',
    [{ from: personas.writer.address, to: counter.address, data: INCREMENT, gas: '0x30d40' }],
    [personas.observer.did],
  );
  expect(writerIncrement.status, JSON.stringify(writerIncrement.raw)).toBe(200);
  expect(writerIncrement.result).toMatch(/^0x[0-9a-f]{64}$/i);
  const writerReceipt = await waitForReceipt(request, writerIncrement.result!);

  const targetIncrement = await proxyRpc<string>(
    request,
    personas.target.token,
    orgA.id,
    'eth_sendTransaction',
    [{ from: personas.target.address, to: counter.address, data: INCREMENT, gas: '0x30d40' }],
  );
  expect(targetIncrement.status, JSON.stringify(targetIncrement.raw)).toBe(200);
  expect(targetIncrement.result).toMatch(/^0x[0-9a-f]{64}$/i);
  const targetReceipt = await waitForReceipt(request, targetIncrement.result!);
  await waitForExplorerTransaction(request, personas.writer.token, writerIncrement.result!);
  await waitForExplorerTransaction(request, personas.target.token, targetIncrement.result!);
  await waitForExplorerTransaction(request, personas.admin.token, mintHash);

  const disclosures: DemoDisclosureGrant[] = [];
  const targetUser = await sa.findUserByExternalId(personas.target.did);
  if (!targetUser) throw new Error('Target user disappeared before disclosure setup');
  for (const [requester, level] of [
    ['fullAuditor', 'full'],
    ['pseudonymousAuditor', 'pseudonymous'],
    ['redactedAuditor', 'redacted'],
  ] as const) {
    disclosures.push(await createDisclosure(
      request, adminToken, personas.target.token, orgA.id,
      targetUser, personas[requester], requester, level,
    ));
  }

  // Seed one post-grant RPC audit entry so every disclosure level can verify
  // its independently-scoped activity-log view.
  const auditedCall = await proxyRpc<string>(
    request,
    personas.target.token,
    orgA.id,
    'eth_call',
    [{ from: personas.target.address, to: counter.address, data: COUNT }, 'latest'],
  );
  expect(auditedCall.status, JSON.stringify(auditedCall.raw)).toBe(200);
  expect(BigInt(auditedCall.result!)).toBe(2n);

  const forwardedIncrementData = encodeForwardCall(counter.address, INCREMENT);
  const forwardedIncrement = await proxyRpc<string>(
    request,
    personas.writer.token,
    orgA.id,
    'eth_sendTransaction',
    [{ from: personas.writer.address, to: forwarder.address, data: forwardedIncrementData, gas: '0x30d40' }],
    [personas.observer.did],
  );
  expect(forwardedIncrement.status, JSON.stringify(forwardedIncrement.raw)).toBe(200);
  expect(forwardedIncrement.result).toMatch(/^0x[0-9a-f]{64}$/i);
  const forwardedIncrementReceipt = await waitForReceipt(request, forwardedIncrement.result!);
  await waitForExplorerTransaction(request, personas.writer.token, forwardedIncrement.result!);

  await adminPut(request, adminToken, `/api/v1/admin/orgs/${orgA.id}/compliance/config`, {
    enabled: true,
    threshold_fiat: 1_000,
    currency: 'usd',
    unknown_price_policy: 'forbidden',
    enforcement_mode: 'enforce',
  });
  await adminPut(request, adminToken, `/api/v1/admin/orgs/${orgA.id}/compliance/tokens/${token.address}`, {
    symbol: 'DEMO', decimals: 18, prices: { usd: 2, eur: 4 }, coingecko_id: null,
  });

  const manifest: DemoScenarioManifest = {
    version: 1,
    runId,
    revisions: {
      proxy: process.env.PROXY_GIT_COMMIT || 'unknown',
      explorer: process.env.EXPLORER_GIT_COMMIT || 'unknown',
      indexer: process.env.INDEXER_VERSION || 'unknown',
    },
    orgs: { a: { id: orgA.id, slug: orgA.slug }, b: { id: orgB.id, slug: orgB.slug } },
    personas,
    contracts: {
      counter: { address: counter.address, deploymentHash: counter.hash, abi: counter.abi },
      token: { address: token.address, deploymentHash: token.hash, abi: token.abi },
      forwarder: { address: forwarder.address, deploymentHash: forwarder.hash, abi: forwarder.abi },
    },
    transactions: {
      writerMint: {
        hash: mintHash,
        blockNumber: Number.parseInt(mintReceipt.blockNumber, 16),
        from: personas.admin.address,
        to: token.address,
        value: '0x0',
        input: encodeMintCall(personas.writer.address, mintAmount),
      },
      writerIncrement: {
        hash: writerIncrement.result!, blockNumber: Number.parseInt(writerReceipt.blockNumber, 16),
        from: personas.writer.address, to: counter.address, value: '0x0', input: INCREMENT,
      },
      targetIncrement: {
        hash: targetIncrement.result!, blockNumber: Number.parseInt(targetReceipt.blockNumber, 16),
        from: personas.target.address, to: counter.address, value: '0x0', input: INCREMENT,
      },
      writerForwardedIncrement: {
        hash: forwardedIncrement.result!,
        blockNumber: Number.parseInt(forwardedIncrementReceipt.blockNumber, 16),
        from: personas.writer.address,
        to: forwarder.address,
        value: '0x0',
        input: forwardedIncrementData,
      },
    },
    disclosures,
    eventTopics: { countIncremented: countIncremented.topic0 },
    canaries: {
      protectedAddresses: [personas.writer.address, personas.target.address, forwarder.address],
      transactionHashes: [writerIncrement.result!, targetIncrement.result!, forwardedIncrement.result!, mintHash],
      calldata: [INCREMENT, forwardedIncrementData, encodeMintCall(personas.writer.address, mintAmount)],
    },
    cleanup: { orgIds: [orgA.id, orgB.id], sanctions: [] },
  };
  await writeDemoManifest(manifest);
});
