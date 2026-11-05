import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {argumentsFor,explicitSelection,sourceSelection,selectedContext,preparedSelection,parsePreparedResult} from '../examples/configuration.mjs';

const org='00000000-0000-4000-8000-000000000001';
const scope={kind:'organization',id:org};
const source=(kind='groups')=>JSON.stringify({apiVersion:'ops.configuration/v1',kind,scope,baseRevision:0,spec:{groups:[]}});
const revision=(kind='groups',id='draft')=>({id,kind,scope,digest:`digest-${id}`});
const none={configuredConsumer:'none',activationSupported:false,candidateReviewSupported:true,referenceSimulationSupported:true,nodePreviewSupported:false,unavailableReason:'execution_consumer_unavailable'};
const guarded={configuredConsumer:'guarded-reth',activationSupported:true,candidateReviewSupported:true,referenceSimulationSupported:false,nodePreviewSupported:true};

test('source routing infers all supported streams without a default and validates explicit selection',()=>{
  for(const kind of ['groups','contract-registry','execution-rules','compliance','approvers'])assert.deepEqual(sourceSelection(source(kind)),{kind,scope});
  assert.deepEqual(sourceSelection('{"kind":"platform","scope":{"kind":"platform"}}'),{kind:'platform',scope:{kind:'platform'}});
  assert.throws(()=>sourceSelection(source(),{kind:'execution-rules'}),/conflicts/);
  assert.throws(()=>sourceSelection(source(),{orgId:'other'}),/conflicts/);
  assert.throws(()=>sourceSelection('{"kind":"platform","scope":{"kind":"platform"}}',{orgId:org}),/no organization/);
  assert.throws(()=>sourceSelection('{"kind":"future","scope":{}}'),/supported/);
  assert.throws(()=>sourceSelection('{"kind":"groups","scope":{"kind":"platform"}}'),/Organization/);
  assert.throws(()=>sourceSelection('{"kind":"groups"'),SyntaxError);
});

test('routing refuses duplicate, escaped, case-variant and ambiguous routing metadata',()=>{
  for(const text of [
    `{"kind":"groups","kind":"compliance","scope":${JSON.stringify(scope)}}`,
    `{"kind":"groups","k\\u0069nd":"groups","scope":${JSON.stringify(scope)}}`,
    `{"Kind":"groups","scope":${JSON.stringify(scope)}}`,
    '{"kind":"groups","scope":{"kind":"organization","id":"a","id":"b"}}',
    '{"kind":"groups","scope":{"Kind":"organization","id":"a"}}',
    `{"kind":"groups","scope":${JSON.stringify(scope)},"scope":${JSON.stringify(scope)}}`,
  ])assert.throws(()=>sourceSelection(text),/routing metadata/);
  // Duplicate non-routing keys must still reach the strict server unchanged.
  assert.equal(sourceSelection(source().replace('"spec":','"spec":{},"spec":')).kind,'groups');
  assert.equal(sourceSelection(source().replace('"spec":','"ignored":[{"kind":"x","scope":{"id":"x"}}],"spec":')).kind,'groups');
});

test('context and ID-only activation need explicit scope; flags and environment must agree',()=>{
  assert.throws(()=>selectedContext({}),/explicitly/);
  assert.throws(()=>selectedContext({kind:'groups'}),/declared ID/);
  assert.deepEqual(selectedContext({kind:'platform'}),{kind:'platform',scope:{kind:'platform'}});
  assert.throws(()=>explicitSelection({kind:'groups'},{OPS_CONFIGURATION_KIND:'compliance'}),/conflicts/);
  assert.throws(()=>explicitSelection({org:'a'},{OPS_ORG_ID:'b'}),/conflicts/);
  assert.throws(()=>argumentsFor(['--kind','groups','--kind','compliance'],['kind']),/repeated/);
  assert.throws(()=>parsePreparedResult('{"selection":{},"selection":{}}'),/routing metadata/);
  assert.throws(()=>preparedSelection({selection:{kind:'groups',scope}}),/prepared/);
});

async function runExample(script,args,env,handler) {
  const calls=[];
  const cleanEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('OPS_')));
  const child=spawn(process.execPath,['--import',new URL('./example-fetch.mjs',import.meta.url).pathname,new URL(`../examples/${script}.mjs`,import.meta.url).pathname,...args],{
    env:{...cleanEnv,OPS_URL:'http://localhost:8080',OPS_ACCESS_TOKEN:'named-test-session',...env},stdio:['ignore','pipe','pipe','ipc']});
  child.on('message',async call=>{
    calls.push(call);
    try {child.send({id:call.id,...await handler(call,calls)});}
    catch(error) {child.send({id:call.id,status:500,body:{error:error.message}});}
  });
  let stdout='',stderr='';child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);
  const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve);});
  return {code,stdout,stderr,calls};
}
async function fileFixture(t,files) {
  const directory=await mkdtemp(join(tmpdir(),'ops-sdk-examples-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const paths={};for(const[name,text]of Object.entries(files)){paths[name]=join(directory,name);await writeFile(paths[name],text);}
  return paths;
}
function workflowHandler(options={}) {
  const {kind='groups',siblings=[]}=options;
  const capabilities=Object.hasOwn(options,'capabilities')?options.capabilities:none;
  return call=>{
    if(call.path.endsWith('/context'))return {body:{capabilities:{executionPolicy:capabilities}}};
    if(call.path.endsWith('/simulate'))return {body:{revisions:[revision(kind),...siblings]}};
    if(call.path.endsWith('/activate')||call.path.endsWith('/activate-ci'))return {body:{revisions:[revision(kind)]}};
    return {status:201,body:revision(kind)};
  };
}

test('prepare sends exact bytes and performs context, submission, review without activation',async t=>{
  const exact=` \n${source().replace('"spec":','"spec":{},"spec":')}\n`;
  const files=await fileFixture(t,{'source.json':exact});
  const result=await runExample('prepare',[files['source.json']],{},workflowHandler());
  assert.equal(result.code,0,result.stderr);
  assert.deepEqual(result.calls.map(c=>c.method),['GET','POST','POST']);
  assert.equal(result.calls[1].body,exact);
  assert.equal(result.calls[1].authorization,'Bearer named-test-session');
  assert.equal(result.calls.some(c=>c.path.endsWith('/activate')),false);
  const prepared=JSON.parse(result.stdout);assert.deepEqual(prepared.selection,{kind:'groups',scope});
  assert.deepEqual(prepared.coactivate,[]);
});

test('platform preparation routes without a fictitious organization',async t=>{
  const files=await fileFixture(t,{'platform.json':'{"kind":"platform","scope":{"kind":"platform"}}'});
  const result=await runExample('prepare',[files['platform.json']],{},call=>({body:call.path.endsWith('/context')?{}:call.path.endsWith('/simulate')?{revisions:[{...revision('platform'),scope:{kind:'platform'}}]}:{...revision('platform'),scope:{kind:'platform'}}}));
  assert.equal(result.code,0,result.stderr);
  assert.ok(result.calls.every(call=>call.path.startsWith('/api/v1/admin/configuration/platform/')));
});

test('routing errors refuse before any HTTP request; context-only selection remains explicit',async t=>{
  const files=await fileFixture(t,{'source.json':source()});
  for(const args of [[],[files['source.json'],'--kind','execution-rules'],['draft']]) {
    const script=args[0]==='draft'?'activate':'prepare';
    const result=await runExample(script,args,{},workflowHandler());
    assert.notEqual(result.code,0);assert.equal(result.calls.length,0);
  }
  const context=await runExample('prepare',['--kind','groups','--org',org],{},workflowHandler());
  assert.equal(context.code,0,context.stderr);assert.equal(context.calls.length,1);
});

test('legacy and missing execution capabilities block direct and sibling activation, not ordinary governance',async()=>{
  for(const capabilities of [none,undefined]) {
    const direct=await runExample('activate',['draft','--kind','execution-rules','--org',org],{},workflowHandler({capabilities,kind:'execution-rules'}));
    assert.notEqual(direct.code,0);assert.match(direct.stderr,/Execution action unavailable/);assert.equal(direct.calls.length,2);
    const sibling=await runExample('activate',['draft','--kind','groups','--org',org],{OPS_COACTIVATE:'execution'},workflowHandler({capabilities,siblings:[revision('execution-rules','execution')]}));
    assert.notEqual(sibling.code,0);assert.equal(sibling.calls.length,2);
  }
  const ordinary=await runExample('activate',['draft','--kind','groups','--org',org],{},workflowHandler({capabilities:undefined}));
  assert.equal(ordinary.code,0,ordinary.stderr);assert.equal(ordinary.calls.length,3);
});

test('guarded consumer permits an explicit separately approved activation',async()=>{
  const result=await runExample('activate',['draft','--kind','execution-rules','--org',org],{},workflowHandler({capabilities:guarded,kind:'execution-rules'}));
  assert.equal(result.code,0,result.stderr);assert.equal(result.calls.at(-1).path.endsWith('/activate'),true);
});

test('CI invocation retains digest binding and the same unsupported-execution fence',async t=>{
  const approval={candidateDigests:{'execution-rules':'digest-draft'},signature:'independent-external-signature'};
  const files=await fileFixture(t,{'approval.json':JSON.stringify(approval)});
  const args=['draft',files['approval.json'],'--kind','execution-rules','--org',org];
  const denied=await runExample('activate',args,{},workflowHandler({kind:'execution-rules'}));
  assert.notEqual(denied.code,0);assert.equal(denied.calls.length,2);
  const allowed=await runExample('activate',args,{},workflowHandler({capabilities:guarded,kind:'execution-rules'}));
  assert.equal(allowed.code,0,allowed.stderr);
  assert.ok(allowed.calls.at(-1).path.endsWith('/activate-ci'));
  assert.deepEqual(JSON.parse(allowed.calls.at(-1).body).approval,approval);
});

test('prepared metadata is rebound to fresh exact scope, candidate IDs and digests',async t=>{
  const prepared={selection:{kind:'groups',scope},draft:revision(),coactivate:[],review:{revisions:[revision()]},candidateDigests:{groups:'digest-draft'}};
  const files=await fileFixture(t,{'prepared.json':JSON.stringify(prepared),'stale.json':JSON.stringify({...prepared,candidateDigests:{groups:'stale'}})});
  const valid=await runExample('activate',['--prepared',files['prepared.json']],{},workflowHandler());
  assert.equal(valid.code,0,valid.stderr);assert.equal(valid.calls.length,3);
  const stale=await runExample('activate',['--prepared',files['stale.json']],{},workflowHandler());
  assert.notEqual(stale.code,0);assert.match(stale.stderr,/differs from prepared/);assert.equal(stale.calls.length,2);
  const wrong=await runExample('activate',['--prepared',files['prepared.json']],{},call=>call.path.endsWith('/simulate')?{body:{revisions:[{...revision(),scope:{kind:'organization',id:'other'}}]}}:workflowHandler()(call));
  assert.notEqual(wrong.code,0);assert.match(wrong.stderr,/scope does not match/);assert.equal(wrong.calls.length,2);
});

test('unavailable requested node preview fails before draft submission; no-preview drafting remains available',async t=>{
  const files=await fileFixture(t,{'source.json':source('execution-rules'),'preview.json':'{"method":"eth_call","params":[]}'});
  const unavailable=await runExample('prepare',[files['source.json']],{OPS_PREVIEW_FILE:files['preview.json']},workflowHandler({kind:'execution-rules'}));
  assert.notEqual(unavailable.code,0);assert.match(unavailable.stderr,/execution_consumer_unavailable/);assert.equal(unavailable.calls.length,1);
  const draft=await runExample('prepare',[files['source.json']],{},workflowHandler({kind:'execution-rules'}));
  assert.equal(draft.code,0,draft.stderr);assert.equal(draft.calls.length,3);assert.match(draft.stderr,/activation unavailable/);
});
