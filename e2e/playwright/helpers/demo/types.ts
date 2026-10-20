export type PersonaName =
  | 'admin'
  | 'reader'
  | 'writer'
  | 'target'
  | 'observer'
  | 'fullAuditor'
  | 'pseudonymousAuditor'
  | 'redactedAuditor'
  | 'outsider'
  | 'orgBMember';

export interface DemoPersona {
  id: string;
  did: string;
  address: string;
  token: string;
  groupId: string;
  orgId: string;
}

export interface DemoContract {
  address: string;
  deploymentHash: string;
  abi: string;
}

export interface DemoTransaction {
  hash: string;
  blockNumber: number;
  from: string;
  to: string;
  value: string;
  input: string;
}

export interface DemoDisclosureGrant {
  requestId: string;
  grantId: string;
  level: 'full' | 'pseudonymous' | 'redacted';
  requester: PersonaName;
}

export interface CleanupResource {
  orgIds: string[];
  sanctions: Array<{ id: string }>;
}

export interface DemoScenarioManifest {
  version: 1;
  runId: string;
  revisions: {
    proxy: string;
    explorer: string;
    indexer: string;
  };
  orgs: {
    a: { id: string; slug: string };
    b: { id: string; slug: string };
  };
  personas: Record<PersonaName, DemoPersona>;
  contracts: {
    counter: DemoContract;
    token: DemoContract;
    forwarder: DemoContract;
  };
  transactions: {
    writerIncrement: DemoTransaction;
    targetIncrement: DemoTransaction;
    writerForwardedIncrement: DemoTransaction;
    writerMint: DemoTransaction;
  };
  disclosures: DemoDisclosureGrant[];
  eventTopics: {
    countIncremented: string;
  };
  canaries: {
    protectedAddresses: string[];
    transactionHashes: string[];
    calldata: string[];
  };
  cleanup: CleanupResource;
}
