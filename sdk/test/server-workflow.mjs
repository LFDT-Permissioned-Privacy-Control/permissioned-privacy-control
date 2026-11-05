// Invoked by TestConfigurationSDKRetainedWorkflow against real OPS HTTP
// handlers and owned PostgreSQL. Application RPC responses are canned; this
// does not exercise an EVM, Guard v1 producer, identity provider or SDK release.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {OpsClient,OpsError} from '../dist/index.js';

const fixture=JSON.parse(process.env.OPS_SDK_WORKFLOW_FIXTURE);
// Counts describe only this explicit fixture, including review and denied RPC
// calls. They establish no generalized workload or request-count improvement.
let requests=0,mutations=0,stateMutationAttempts=0;
const calls=[];
const transport=async(url,init)=>{
  requests++;
  if(init.method!=='GET')mutations++;
  const path=new URL(url).pathname;
  const stateChange=init.method!=='GET'&&!path.startsWith('/rpc/')&&!path.endsWith('/simulate');
  if(stateChange)stateMutationAttempts++;
  const response=await fetch(url,init);
  calls.push({method:init.method,path,status:response.status,stateChange});
  return response;
};
const client=token=>new OpsClient({baseUrl:fixture.baseUrl,session:{accessToken:token},fetch:transport});
const author=client(fixture.author),reviewer=client(fixture.reviewer),member=client(fixture.member);
const org=fixture.orgId,groupId=randomUUID(),contractId=randomUUID(),grantId=randomUUID();
const selected=[];
let onboarded;

async function bundle(first) {
  const groups=await author.context(org,'groups');
  const registry=await author.context(org,'contract-registry');
  assert.equal(groups.capabilities.executionPolicy.configuredConsumer,'none');
  if(first) {
    groups.source.spec.groups.push({id:groupId,slug:'sdk-readers',name:'SDK readers',description:'SDK workflow fixture',
      isOrgAdmin:false,isOrgReadonlyAdmin:false,verboseErrors:false,allowedMethods:['eth_getLogs'],claims:[]});
    registry.source.spec.contracts.push({id:contractId,address:fixture.contract,name:'SDK event privacy',abi:fixture.abi,
      allowVisibleToUnlock:false,eventsAllowDynamicPayload:false,readGrants:[{id:grantId,groupId,legacyClaims:[],
        eventRules:{mode:'allowlist',rules:[{topic0:fixture.allowedTopic,name:'Visible',paramRules:[]}]}}]});
  } else groups.source.spec.groups.find(group=>group.id===groupId).name='SDK readers replay';
  // These are explicit test-authored sources, with no inference or planner.
  const groupSource=` ${JSON.stringify(groups.source,null,2)}\n`;
  const groupDraft=await author.submitDraft(org,'groups',groupSource);
  assert.equal(groupDraft.source,groupSource);
  registry.source.dependencies={...registry.source.dependencies,groups:groupDraft.digest};
  const registrySource=` ${JSON.stringify(registry.source,null,2)}\n`;
  const registryDraft=await author.submitDraft(org,'contract-registry',registrySource);
  assert.equal(registryDraft.source,registrySource);
  const reviewed=await reviewer.reviewDraft(org,'contract-registry',registryDraft.id,[groupDraft.id]);
  assert.ok(Object.isFrozen(reviewed.coactivate));
  assert.deepEqual(reviewed.candidateDigests,{groups:groupDraft.digest,'contract-registry':registryDraft.digest});
  const activated=await reviewer.activateReviewed(reviewed);
  assert.deepEqual(activated.revisions.map(row=>row.id).sort(),[groupDraft.id,registryDraft.id].sort());
  for(const [kind,draft] of [['groups',groupDraft],['contract-registry',registryDraft]]) {
    const stored=await author.revision(org,kind,draft.id);
    assert.equal(stored.status,'active');assert.equal(stored.digest,draft.digest);
  }
  selected.push({groups:groupDraft.id,registry:registryDraft.id});
}

await bundle(true);
onboarded=await reviewer.request('POST /api/v1/admin/orgs/{org_id}/memberships/by-did',{
  path:{org_id:org},body:{did:fixture.memberDID,group_id:groupId}});
await member.request('POST /api/v1/eth/link/verify',{body:{nonce:fixture.linkNonce,address:fixture.wallet,signature:fixture.linkSignature}});
const linked=await member.request('GET /api/v1/eth/addresses',{});
assert.ok(linked.addresses.some(link=>link.address===fixture.wallet));

const logs=await member.rpc(org,'eth_getLogs',[{address:fixture.contract,fromBlock:'latest',toBlock:'latest'}]);
assert.equal(logs.length,1);assert.equal(logs[0].topics[0],fixture.allowedTopic);
await assert.rejects(member.rpc(org,'eth_getBalance',[fixture.wallet,'latest']),error=>error instanceof OpsError&&error.status===404);

// An incident ban is operational state, outside either document. Replaying
// exported documents must not undo the ban or replace the membership/address.
await reviewer.request('PUT /api/v1/admin/users/{user_id}',{path:{user_id:onboarded.user_id},body:{banned:true}});
await bundle(false);
await assert.rejects(member.rpc(org,'eth_getLogs',[{address:fixture.contract,fromBlock:'latest',toBlock:'latest'}]),error=>error instanceof OpsError&&[401,403,404].includes(error.status));
process.stdout.write(JSON.stringify({requests,mutations,stateMutationAttempts,calls,selected,groupId,contractId,grantId,membershipId:onboarded.membership.id,
  checks:['exact_source','independent_coactivation','operational_membership','real_wallet_link','method_deny','event_privacy_filter','operational_facts_survive_replay'],
  applicationNode:'canned JSON-RPC; no EVM/producer execution',guardV1ProducerChecked:false})+'\n');
